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
    message_redaction_regex_list => list()
}.

-spec format(logger:log_event(), logger:formatter_config()) -> unicode:chardata().

format(#{msg := {report, _}} = Msg, Config) ->
    Data = logger_formatter:format(Msg, #{template => [msg]}),
    format(Msg#{msg => {string, Data}}, Config#{exclude_meta_fields => exclude_all});

format(Event, Config) ->
    {Meta, TimeStamp} = get_meta_and_timestamp(Event, Config),
    Severity  = get_severity(Event, Config),
    Message   = get_message(Event),
    {RedactedMsg, RedactedMeta} = redact(Message, Meta, Config),
    PrintableMeta = meta_to_printable(RedactedMeta),
    Formatted = create_message(RedactedMsg, Severity, TimeStamp, PrintableMeta),
    Encoded = jsx:encode(Formatted),
    [Encoded, <<"\n">>].

get_severity(Event, Config) ->
    LogLevelMap = maps:get(log_level_map, Config, #{}),
    Level = maps:get(level, Event),
    maps:get(Level, LogLevelMap, Level).

get_meta_and_timestamp(#{meta := Meta0}, Config) ->
    {Meta, TimeStamp} = case get_timestamp(Meta0) of
        {error, _} ->
            USec = os:system_time(microsecond),
            {ok, TS} = rfc3339:format(USec, microsecond),
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
    ExcludedFields = maps:get(exclude_meta_fields, Config, get_default_excludes()),
    maps:without(ExcludedFields, Meta).

get_message(#{msg := Message}) ->
    do_get_message(Message).

do_get_message({string, Message}) when is_list(Message) ->
    unicode:characters_to_binary(Message, unicode);
do_get_message({string, Message}) when is_binary(Message) ->
    Message;
do_get_message({report, _Report}) ->
    erlang:throw({formatter_error, unexpected_report}); % there shouldn't be any reports here
do_get_message({Format, Args}) ->
    unicode:characters_to_binary(io_lib:format(Format, Args), unicode).

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
    maps:fold(fun add_meta/3, #{}, Meta).

add_meta(K, V, Map) ->
    {Key, Value} = printable({K, V}),
    Map#{Key => Value}.

%% can't naively encode `File` or `Pid` as json as jsx see them as lists
%% of integers
printable({file, File}) ->
    {file, unicode:characters_to_binary(File, unicode)};
printable({Key, Pid}) when is_pid(Pid) ->
    {Key, pid_to_binary(Pid)};
printable({Key, Port}) when is_port(Port) ->
    {Key, unicode:characters_to_binary(erlang:port_to_list(Port), unicode)};
printable({Key, {A, B, C} = V}) when not is_integer(A); not is_integer(B); not is_integer(C) ->
    % jsx:is_term treats all 3 length tuples as timestamps and fails if they are actually not
    % so we filter tuples, that are definetly not timestamps
    {Key, unicode:characters_to_binary((io_lib:format("~p", [V])), unicode)};

%% if a value is expressable in json use it directly, otherwise
%% try to get a printable representation and express it as a json
%% string
printable({Key, Value}) when is_atom(Key); is_binary(Key) ->
    case jsx:is_term(Value) of
        true  -> {Key, Value};
        false -> {Key, unicode:characters_to_binary(io_lib:format("~p", [Value]), unicode)}
    end.

pid_to_binary(Pid) ->
    unicode:characters_to_binary(pid_to_list(Pid), unicode).

redact(Message, Meta, Config) ->
    Regexes = maps:get(message_redaction_regex_list, Config, []),
    {redact_all(Message, Regexes), traverse_and_redact(Meta, Regexes)}.

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

traverse_and_redact(Map, Regexes) when is_map(Map)->
    F = fun (K, V, Acc) ->
        Acc#{K => traverse_and_redact(V, Regexes)}
    end,
    maps:fold(F, #{}, Map);

traverse_and_redact(List, Regexes) when is_list(List) ->
    F = fun(V, Acc) ->
        [traverse_and_redact(V, Regexes) | Acc]
    end,
    lists:reverse(lists:foldl(F, [], List));

traverse_and_redact(Tuple, Regexes) when is_tuple(Tuple) ->
    traverse_and_redact(tuple_to_list(Tuple), Regexes);

traverse_and_redact(Binary, Regexes) when is_binary(Binary) ->
    redact_all(Binary, Regexes);

traverse_and_redact(Item, _) ->
    Item.

get_default_excludes() ->
    [gl, domain].

% TO DO: tests
