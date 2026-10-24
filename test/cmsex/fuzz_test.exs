defmodule Cmsex.FuzzTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  # Long runs of the robustness properties, left out of `mix test`:
  #
  #     mix test --only fuzz
  #     FUZZ_ROUNDS=100000 mix test --only fuzz
  #
  # A failure prints the seed of the run; `mix test --only fuzz --seed N`
  # repeats it.

  alias Cmsex.{TestFixtures, TestFuzz}

  @moduletag :fuzz
  @moduletag timeout: :infinity

  @rounds String.to_integer(System.get_env("FUZZ_ROUNDS", "5000"))

  setup_all do
    %{corpus: TestFuzz.corpus(), roots: TestFixtures.roots()}
  end

  property "changed messages are read or refused, never raise", ctx do
    check all {name, edits, input} <- TestFuzz.mutated(ctx.corpus), max_runs: @rounds do
      assert TestFuzz.bad_results(input, ctx.roots) == [],
             "#{name} with #{inspect(edits)}"
    end
  end

  property "random bytes are refused, never raise", ctx do
    check all input <- TestFuzz.random(), max_runs: @rounds do
      assert TestFuzz.bad_results(input, ctx.roots) == []
    end
  end
end
