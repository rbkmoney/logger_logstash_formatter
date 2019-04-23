%%% @doc Public API, supervisor and application startup.
%%% @end

-module(logger_logstash_formatter).

%% API
-export([format/2]).

%%
%% API
%%

%% Types
-export_type([config/0]).

-export_type([log_level_map/0]).

-type log_level_map() :: #{logger:level() => atom()}.

-type config() :: #{
    exclude_meta_fields => [atom()] | exclude_all,
    log_level_map => log_level_map(),
    message_redaction_regex_list => list(),
    single_line_message => boolean()
}.

-define(DEFAULT_EXCLUDES, [gl, domain]).

-spec format(logger:log_event(), logger:formatter_config()) -> unicode:chardata().

format(#{msg := {report, _}} = Msg, Config) ->
    Data = logger_formatter:format(Msg, #{template => [msg]}),
    format(Msg#{msg => {string, Data}}, Config#{exclude_meta_fields => exclude_all});

format(Event, Config) ->
    {Meta, TimeStamp} = get_meta_and_timestamp(Event, Config),
    Severity  = get_severity(Event, Config),
    Message   = get_message(Event, Config),
    {RedactedMsg, RedactedMeta} = redact(Message, Meta, Config),
    PrintableMeta = meta_to_printable(RedactedMeta),
    Formatted = create_message(RedactedMsg, Severity, TimeStamp, PrintableMeta),
    Encoded = jsx:encode(Formatted),
    [Encoded, <<"\n">>].

get_severity(Event, Config) ->
    LogLevelMap = maps:get(log_level_map, Config, #{}),
    Level = maps:get(level, Event),
    maps:get(Level, LogLevelMap, Level).

format_time(USec) ->
    {ok, TS} = rfc3339:format(USec, microsecond),
    TS.

get_meta_and_timestamp(#{meta := Meta0}, Config) ->
    {Meta, TimeStamp} = case get_timestamp(Meta0) of
        {error, _} ->
            TS = format_time(os:system_time(microsecond)),
            {Meta0, TS};
        TS ->
            % Succesfully got time from meta, can remove the field now
            {maps:remove(time, Meta0), TS}
        end,
    {reduce_meta(Meta, Config), TimeStamp}.

-spec get_timestamp(logger:metadata()) -> binary() | {error, no_time}.
get_timestamp(Meta) ->
    case maps:get(time, Meta, undefined) of
        USec when is_integer(USec) ->
            {ok, TimeStamp} = rfc3339:format(USec, microsecond),
            TimeStamp;
        _ ->
            {error, no_time}
    end.

reduce_meta(_, #{exclude_meta_fields := exclude_all}) ->
    #{};
reduce_meta(Meta, Config) ->
    ExcludedFields = maps:get(exclude_meta_fields, Config, ?DEFAULT_EXCLUDES),
    maps:without(ExcludedFields, Meta).

get_message(#{msg := Message}, Config) ->
    do_get_message(Message, Config).

do_get_message({string, Message}, _Config) when is_list(Message) ->
    unicode:characters_to_binary(Message, unicode);
do_get_message({string, Message}, _Config) when is_binary(Message) ->
    Message;
do_get_message({report, _Report}, _Config) ->
    erlang:throw({formatter_error, unexpected_report}); % there shouldn't be any reports here
do_get_message({Format, Args}, Config) ->
    FormatList = io_lib:scan_format(Format, Args),
    NewFormatList = reformat(FormatList, Config),
    unicode:characters_to_binary(io_lib:build_text(NewFormatList), unicode).

-spec reformat(FormatList, config()) -> FormatList when
    FormatList :: [char() | io_lib:format_spec()].
reformat(FormatList, Config) ->
    IsSingleLine = maps:get(single_line_message, Config, true),
    try_reformat_single_line(IsSingleLine, FormatList).

try_reformat_single_line(true, FormatList) ->
    lists:map(fun do_reformat_single_line/1, FormatList);
try_reformat_single_line(false, FormatList) ->
    FormatList.

-spec do_reformat_single_line(FormatItem) -> FormatItem when
    FormatItem :: char() | io_lib:format_spec().
do_reformat_single_line(#{control_char := C} = Spec) when C =:= $p orelse C =:= $P->
    Spec#{width => 0};
do_reformat_single_line(C) ->
    C.

create_message(Message, Severity, TimeStamp, Meta) ->
    maps:merge(
        Meta,
        #{
            '@severity'  => Severity,
            '@timestamp' => TimeStamp,
            message      => Message
        }
    ).

meta_to_printable(Meta) ->
    maps:map(fun printable/2, Meta).

%% can't naively encode `File` or `Pid` as json as jsx see them as lists
%% of integers
printable(file, File) ->
    unicode:characters_to_binary(File, unicode);
printable(_, Pid) when is_pid(Pid) ->
    pid_to_binary(Pid);
printable(_, Port) when is_port(Port) ->
    unicode:characters_to_binary(erlang:port_to_list(Port), unicode);
printable(_, {A, B, C} = V) when not is_integer(A); not is_integer(B); not is_integer(C) ->
    % jsx:is_term treats all 3 length tuples as timestamps and fails if they are actually not
    % so we filter tuples, that are definetly not timestamps
    unicode:characters_to_binary((io_lib:format("~w", [V])), unicode);

%% if a value is expressable in json use it directly, otherwise
%% try to get a printable representation and express it as a json
%% string
printable(Key, Value) when is_atom(Key); is_binary(Key) ->
    case jsx:is_term(Value) of
        true  -> Value;
        false -> unicode:characters_to_binary(io_lib:format("~p", [Value]), unicode)
    end.

pid_to_binary(Pid) ->
    unicode:characters_to_binary(pid_to_list(Pid), unicode).

redact(Message, Meta, Config) ->
    Regexes = maps:get(message_redaction_regex_list, Config, []),
    {redact_all(Message, Regexes), traverse_and_redact(Meta, Regexes)}.

redact_all(Message, []) ->
    Message;

redact_all(Message, Regexes) ->
    lists:foldl(fun redact_one/2, Message, Regexes).

redact_one(Regex, Message) ->
    case re:run(Message, compile_regex(Regex), [global, {capture, first, index}]) of
        {match, Captures} ->
            lists:foldl(fun redact_capture/2, Message, Captures);
        nomatch ->
            Message
    end.

redact_capture({S, Len}, Message) ->
    <<Pre:S/binary, _:Len/binary, Rest/binary>> = Message,
    <<Pre/binary, (binary:copy(<<"*">>, Len))/binary, Rest/binary>>;
redact_capture([Capture], Message) ->
    redact_capture(Capture, Message).

compile_regex(Regex) ->
    case application:get_env(?MODULE, message_redaction_compiled_regexes, #{}) of
        #{Regex := CompiledRegex} ->
            CompiledRegex;
        #{} = CompiledRegexes ->
            {ok, CompiledRegex} = re:compile(Regex, [unicode]),
            ok = application:set_env(
                ?MODULE,
                message_redaction_compiled_regexes,
                CompiledRegexes#{Regex => CompiledRegex}
            ),
            CompiledRegex
    end.

traverse_and_redact(V, []) ->
    V;

traverse_and_redact(Map, Regexes) when is_map(Map)->
    F = fun (_, V) ->
        traverse_and_redact(V, Regexes)
    end,
    maps:map(F, Map);

traverse_and_redact(List, Regexes) when is_list(List) ->
    F = fun(V) ->
        traverse_and_redact(V, Regexes)
    end,
    lists:map(F, List);

traverse_and_redact(Tuple, Regexes) when is_tuple(Tuple) ->
    erlang:list_to_tuple(traverse_and_redact(erlang:tuple_to_list(Tuple), Regexes));

traverse_and_redact(Binary, Regexes) when is_binary(Binary) ->
    redact_all(Binary, Regexes);

traverse_and_redact(Item, _) ->
    Item.

-ifdef(TEST) .
-include_lib("eunit/include/eunit.hrl").

create_log_event(Level, Message, Meta) ->
    #{
        level => Level,
        msg => Message,
        meta => Meta
    }.

parse_log_line([Line, _]) ->
    jsx:decode(Line, [return_maps, {labels, existing_atom}]).

get_time() ->
    % we need to override logger time for testing purposes
    USec = os:system_time(microsecond),
    {USec, format_time(USec)}.

-spec test() -> _.  % auto generated eunit function

-spec basic_test_() -> _.
basic_test_() ->
    {USec, BinTime} = get_time(),
    Event0 = create_log_event(info, {string, "The simplest log ever"}, #{time => USec}),
    Event1 = create_log_event(info, {"The simplest ~p ever", ["log"]}, #{time => USec}),
    Event2 = create_log_event(info, {report, "The simplest log ever"}, #{time => USec}),
    [
        {"Basic log", ?_assertEqual(
            create_message(<<"The simplest log ever">>, <<"info">>, BinTime, #{}),
            parse_log_line(format(Event0, #{}))
        )},
        {"Formated log", ?_assertEqual(
            create_message(<<"The simplest \"log\" ever">>, <<"info">>, BinTime, #{}),
            parse_log_line(format(Event1, #{}))
        )},
        {"Report log", ?_assertEqual(
            create_message(<<"The simplest log ever">>, <<"info">>, BinTime, #{}),
            parse_log_line(format(Event2, #{}))
        )}
    ].

-spec redact_test_() -> _.
redact_test_() ->
    {USec, BinTime} = get_time(),
    Event0 = create_log_event(info, {string, "CVC: 424"}, #{time => USec}),
    Event1 = create_log_event(info, {"CVC: ~p", [424]}, #{time => USec}),
    Event2 = create_log_event(info, {string, "No message"}, #{
        time => USec,
        cvc => <<"424">>,
        cvc_list => [<<"434">>, <<"424">>],
        cvc_map => #{my_code => <<"424">>},
        deep_cvc => #{your_code => [<<"434">>, <<"424">>]},
        cvc_tuple => {<<"424">>, gotcha}
    }),
    Expected = create_message(<<"CVC: ***">>, <<"info">>, BinTime, #{}),
    [
        {"String redact", ?_assertEqual(
            Expected,
            parse_log_line(format(Event0, #{message_redaction_regex_list => [<<"424">>]}))
        )},
        {"Format redact", ?_assertEqual(
            Expected,
            parse_log_line(format(Event1, #{message_redaction_regex_list => [<<"424">>]})) % equals Event0 format
        )},
        {"Meta redact", ?_assertEqual(
            create_message(<<"No message">>, <<"info">>, BinTime, #{
                cvc => <<"***">>,
                cvc_list => [<<"434">>, <<"***">>],
                cvc_map => #{my_code => <<"***">>},
                deep_cvc => #{your_code => [<<"434">>, <<"***">>]},
                cvc_tuple => <<"{<<\"***\">>,gotcha}">>
            }),
            parse_log_line(format(Event2, #{message_redaction_regex_list => [<<"424">>]}))
        )}
    ].

-spec excludes_test_() -> _.
excludes_test_() ->
    {USec, BinTime} = get_time(),
    BinPid = pid_to_binary(self()),
    Event = create_log_event(info, {string, "Excludes"}, #{
        time => USec,
        gl => self(),
        domain => [rbkmoney],
        answer => 42
    }),
    [
        {"Default excludes", ?_assertEqual(
            create_message(<<"Excludes">>, <<"info">>, BinTime, #{answer => 42}),
            parse_log_line(format(Event, #{}))
        )},
        {"No excludes", ?_assertEqual(
            create_message(<<"Excludes">>, <<"info">>, BinTime, #{
                gl => BinPid,
                domain => [<<"rbkmoney">>],
                answer => 42
            }),
            parse_log_line(format(Event, #{exclude_meta_fields => []}))
        )},
        {"Custom excludes", ?_assertEqual(
            create_message(<<"Excludes">>, <<"info">>, BinTime, #{gl => BinPid, domain => [<<"rbkmoney">>]}),
            parse_log_line(format(Event, #{exclude_meta_fields => [answer]}))
        )},
        {"Exlude all", ?_assertEqual(
            create_message(<<"Excludes">>, <<"info">>, BinTime, #{}),
            parse_log_line(format(Event, #{exclude_meta_fields => exclude_all}))
        )}
    ].

-spec level_mapping_test_() -> _.
level_mapping_test_() ->
    {USec, BinTime} = get_time(),
    Event = create_log_event(info, {string, "Mapping"}, #{time => USec}),
    [
        {"Level mapping", ?_assertEqual(
            create_message(<<"Mapping">>, <<"INFORMATION">>, BinTime, #{}),
            parse_log_line(format(Event, #{log_level_map => #{info => 'INFORMATION'}}))
        )}
    ].

-spec line_break_exists_and_single_test() -> _.
line_break_exists_and_single_test() ->
    Event = create_log_event(info, {string, "Line break"}, #{}),
    [_, <<"\n">>] = format(Event, #{}).

-spec single_line_reformat_test_() -> _.
single_line_reformat_test_() ->
    {USec, BinTime} = get_time(),
    ComplexpEvent = create_log_event(info, {"Complex ~1p", [[1, 2, 3]]}, #{time => USec}),
    ComplexPEvent = create_log_event(info, {"Complex ~1P", [[1, 2, 3], 100]}, #{time => USec}),
    [
        {"Single line p", ?_assertEqual(
            create_message(<<"Complex [1,2,3]">>, <<"info">>, BinTime, #{}),
            parse_log_line(format(ComplexpEvent, #{single_line_message => true}))
        )},
        {"Single line P", ?_assertEqual(
            create_message(<<"Complex [1,2,3]">>, <<"info">>, BinTime, #{}),
            parse_log_line(format(ComplexPEvent, #{single_line_message => true}))
        )},
        {"Multiple lines p", ?_assertEqual(
            create_message(<<"Complex [1,\n         2,\n         3]">>, <<"info">>, BinTime, #{}),
            parse_log_line(format(ComplexpEvent, #{single_line_message => false}))
        )},
        {"Multiple lines P", ?_assertEqual(
            create_message(<<"Complex [1,\n         2,\n         3]">>, <<"info">>, BinTime, #{}),
            parse_log_line(format(ComplexPEvent, #{single_line_message => false}))
        )}
    ].

-spec various_format_types_test_() -> _.
various_format_types_test_() ->
    {USec, BinTime} = get_time(),
    ValidIOFormats = [
        'Just ~p',
        "Just ~p",
        <<"Just ~p">>
    ],
    [
        [
            {"Without reformat", ?_assertEqual(
                create_message(<<"Just atom">>, <<"info">>, BinTime, #{}),
                parse_log_line(format(
                    create_log_event(info, {F, [atom]}, #{time => USec}),
                    #{single_line_message => false}
                ))
            )},
            {"With reformat", ?_assertEqual(
                create_message(<<"Just atom">>, <<"info">>, BinTime, #{}),
                parse_log_line(format(
                    create_log_event(info, {F, [atom]}, #{time => USec}),
                    #{single_line_message => true}
                ))
            )}
        ]
        || F <- ValidIOFormats
    ].

-endif.
