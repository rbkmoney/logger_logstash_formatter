%%%
%%% Copyright 2020 RBKmoney
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%

-module(logger_logstash_regex_filter).

-define(MESSAGE_TRANSFORM_REGEXES_KEY, logger_logstash_formatter_message_transform_regexes).

%% API
-export([redact/2]).

-type config() :: #{
    regex_list => list()
}.

-spec redact(logger:log_event(), config()) -> logger:filter_return().
redact(Event = #{msg := {report, Report}}, Config) ->
    Regexes = maps:get(regex_list, Config, []),
    Event = #{
        msg => {report, redact_all(Report, Regexes)}
    };
redact(Event = #{msg := Message, meta := Meta}, Config) ->
    Regexes = maps:get(regex_list, Config, []),
    Event = #{
        msg => do_redact(Message, Regexes),
        meta => traverse_and_redact(Meta, Regexes)
    }.

do_redact({string, String}, Regexes) when is_list(String) ->
    do_redact({string, unicode:characters_to_binary(String, unicode)}, Regexes);
do_redact({string, String}, Regexes) when is_binary(String) ->
    {string, redact_all(String, Regexes)};
do_redact({Format, Args}, Regexes) ->
    {Format, [redact_all(Arg, Regexes) || Arg <- Args]}.

redact_all(Message, []) ->
    Message;
redact_all(Message, Regexes) when is_binary(Message) ->
    lists:foldl(fun redact_one/2, Message, Regexes);
redact_all(Message, _) ->
    Message.

redact_one(Regex, Message) ->
    try re:run(Message, compile_regex(Regex), [global, {capture, first, index}]) of
        {match, Captures} ->
            lists:foldl(fun redact_capture/2, Message, Captures);
        nomatch ->
            Message
    catch
        _:badarg ->
            Message
    end.

redact_capture({S, Len}, Message) ->
    <<Pre:S/binary, _:Len/binary, Rest/binary>> = Message,
    <<Pre/binary, (binary:copy(<<"*">>, Len))/binary, Rest/binary>>;
redact_capture([Capture], Message) ->
    redact_capture(Capture, Message).

compile_regex(Regex) ->
    case persistent_term:get(?MESSAGE_TRANSFORM_REGEXES_KEY, #{}) of
        #{Regex := CompiledRegex} ->
            CompiledRegex;
        #{} = CompiledRegexes ->
            {ok, CompiledRegex} = re:compile(Regex, [unicode]),
            persistent_term:put(
                ?MESSAGE_TRANSFORM_REGEXES_KEY,
                CompiledRegexes#{Regex => CompiledRegex}
            ),
            CompiledRegex
    end.

traverse_and_redact(V, []) ->
    V;
traverse_and_redact(Map, Regexes) when is_map(Map) ->
    F = fun(_, V) ->
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

-ifdef(TEST).
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

% auto generated eunit function
-spec test() -> _.


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
        {"String redact",
            ?_assertEqual(
                Expected,
                parse_log_line(format(Event0, #{message_redaction_regex_list => [<<"424">>]}))
            )},
        {"Format redact",
            ?_assertEqual(
                Expected,
                % equals Event0 format
                parse_log_line(format(Event1, #{message_redaction_regex_list => [<<"424">>]}))
            )},
        {"Meta redact",
            ?_assertEqual(
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

-endif.