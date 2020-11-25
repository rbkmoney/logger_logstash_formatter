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

-module(logger_logstash_meta_fields_filter).

%% API
-export([filter/2]).

-define(DEFAULT_EXCLUDES, [gl, domain]).

-type config() :: #{
    exclude_fields => [atom()]
}.

-spec filter(logger:log_event(), config()) -> logger:filter_return().
filter(Event = #{msg := {report, _}}, _) ->
    %% Exclude all metadata for report
    Event#{meta => #{}};
filter(Event = #{meta := Meta}, Config) ->
    ExcludedFields = maps:get(exclude_fields, Config, ?DEFAULT_EXCLUDES),
    Event#{
        meta => maps:without(ExcludedFields, Meta)
    }.

