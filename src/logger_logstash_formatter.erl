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

format(Msg, Config) ->
    Regexes = maps:get(message_redaction_regex_list, Config, []),
    RedactedMsg = redact(get_msg_map(Msg, Config), Regexes),
    Encoded = jsx:encode(RedactedMsg),
    [Encoded, <<"\n">>].

get_msg_map(Msg, Config) ->
    LogLevelMap = maps:get(log_level_map, Config, #{}),
    maps:merge(
        get_metadata(Msg, Config),
        #{
            '@timestamp' => get_timestamp(),
            '@severity'  => get_severity (Msg, LogLevelMap),
            message      => get_message  (Msg)
         }
    ).

-spec get_timestamp() -> binary().
get_timestamp() ->
    USec = os:system_time(microsecond),
    {ok, TimeStamp} = rfc3339:format(USec, microsecond),
    TimeStamp.

-spec get_severity(logger:log_event(), log_level_map()) -> atom().
get_severity(Msg, LogLevelMap) ->
    Level = maps:get(level, Msg),
    maps:get(Level, LogLevelMap, Level).

-spec get_message(logger:log_event()) -> binary().
get_message(Msg) ->
    case maps:get(msg, Msg) of
        {string, Message} when is_list(Message)->
            unicode:characters_to_binary(Message, unicode);
        {string, Message} when is_binary(Message)->
            Message;
        {report, _Report} ->
            erlang:throw({formatter_error, unexpected_report}); % there shouldn't be any reports here
        {Format, Args} ->
            unicode:characters_to_binary(io_lib:format(Format, Args), unicode)
    end.

-spec get_metadata(logger:log_event(), [atom()]) -> logger:metadata().
get_metadata(Msg, Config) ->
    ExcludedFields = maps:get(exclude_meta_fields, Config, get_default_excludes()),
    case ExcludedFields of
        exclude_all ->
            #{};
        _ ->
            Meta0 = maps:without(ExcludedFields, maps:get(meta, Msg)),
            Meta = case maps:get(message_redaction_regex_list, Config, []) of
                [] ->
                    Meta0;
                Regexes ->
                    traverse_and_redact(Meta0, Regexes)
            end,
            maps:fold(fun add_meta/3, #{}, Meta)
    end.

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

%%filters
redact(#{message := Message} = Msg, Regexes) ->
    Msg#{message => redact_all(Message, Regexes)}.

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

get_default_excludes() ->
    [time, gl, domain].

%% Metadata traversal
% TO DO: Separate this to another module

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

% TO DO: tests
