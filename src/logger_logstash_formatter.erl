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
-type config() :: #{
    exclude_meta_fields => [atom()] | exclude_all,
    message_redaction_regex_list => list()
}.

-spec format(logger:log_event(), logger:formatter_config()) -> unicode:chardata().
format(Msg, Config) ->
    ExcludedFields = maps:get(exclude_meta_fields, Config, get_default_excludes()),
    Regexes = maps:get(message_redaction_regex_list, Config, []),
    RedactedMsg = redact(get_msg_map(Msg, ExcludedFields), Regexes),
    Encoded = jsx:encode(RedactedMsg),
    <<Encoded/binary, "\n">>.

get_msg_map(Msg, ExcludedFields) ->
    maps:merge(
        get_metadata(Msg, ExcludedFields),
        #{
            '@timestamp' => get_timestamp(),
            '@severity'  => get_severity (Msg),
            'message'    => get_message  (Msg)
         }
    ).

-spec get_timestamp() -> binary().
get_timestamp() ->
    {MegaSec, Sec, MicroSec} = os:timestamp(),
    USec = MegaSec * 1000000000000 + Sec * 1000000 + MicroSec,
    {ok, TimeStamp} = rfc3339:format(USec, micro_seconds),
    TimeStamp.

-spec get_severity(logger:log_event()) -> atom().
get_severity(Msg) ->
    maps:get(level, Msg).

-spec get_message(logger:log_event()) -> io_lib:chars().
get_message(Msg) ->
    case maps:get(msg, Msg) of
        {string, Message} when is_list(Message)->
            Message;
        {string, Message} when is_binary(Message)->
            binary_to_list(Message);
        {report, Report} ->
            Report; % No report support so far, stay tuned
        {Format, Args} ->
           io_lib:format(Format, Args)
    end.

-spec get_metadata(logger:log_event(), [atom()]) -> logger:metadata().
get_metadata(Msg, ExcludedFields) ->
    Meta = case ExcludedFields of
        exclude_all ->
            #{};
        _ -> 
            maps:without(ExcludedFields, maps:get(meta, Msg))
    end,
    maps:fold(fun add_meta/3, #{}, Meta).

add_meta(K, V, Map) ->
    {Key, Value} = printable({K, V}),
    Map#{Key => Value}.

%% can't naively encode `File` or `Pid` as json as jsx see them as lists
%% of integers
printable({file, File}) ->
    {file, unicode:characters_to_binary(File, unicode)};
printable({pid, Pid}) ->
    {pid, pid_list(Pid)};

%% if a value is expressable in json use it directly, otherwise
%% try to get a printable representation and express it as a json
%% string
printable({Key, Value}) when is_atom(Key); is_binary(Key) ->
    case jsx:is_term(Value) of
        true  -> {Key, Value};
        false -> {Key, unicode:characters_to_binary(io_lib:format("~p", [Value]), unicode)}
    end.

pid_list(Pid) ->
    try unicode:characters_to_binary(Pid, unicode) of
        Pid0 -> Pid0
    catch error:badarg ->
            unicode:characters_to_binary(hd(io_lib:format("~p", [Pid])), unicode)
    end.

%%filters
redact(#{'message' := Message} = Msg, Regexes) ->
    Msg#{'message' => redact_all(unicode:characters_to_binary(Message, unicode), Regexes)}.

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

% TO DO: tests

