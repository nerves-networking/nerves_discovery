# SPDX-FileCopyrightText: None
# SPDX-License-Identifier: CC0-1.0
defmodule NervesDiscovery.MixProject do
  use Mix.Project

  @version "0.1.1"
  @description "Discover Nerves devices using mDNS"
  @source_url "https://github.com/nerves-networking/nerves_discovery"

  def project do
    [
      app: :nerves_discovery,
      version: @version,
      elixir: "~> 1.15",
      description: @description,
      package: package(),
      source_url: @source_url,
      docs: docs(),
      start_permanent: Mix.env() == :prod,
      dialyzer: [
        flags: [:missing_return, :extra_return, :unmatched_returns, :error_handling, :underspecs]
      ],
      deps: deps()
    ]
  end

  def cli do
    [
      preferred_envs: %{
        dialyzer: :test,
        docs: :docs,
        "hex.build": :docs,
        "hex.publish": :docs,
        credo: :test
      }
    ]
  end

  def application do
    [
      extra_applications: []
    ]
  end

  defp package do
    %{
      files: [
        "CHANGELOG.md",
        "lib",
        "LICENSES",
        "mix.exs",
        "NOTICE",
        "README.md",
        "REUSE.toml"
      ],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => @source_url <> "/blob/main/CHANGELOG.md",
        "REUSE Compliance" =>
          "https://api.reuse.software/info/github.com/nerves-networking/nerves_discovery"
      }
    }
  end

  defp docs do
    [
      extras: ["README.md", "CHANGELOG.md"],
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.27", only: :docs, runtime: false},
      {:mimic, "~> 1.7", only: :test}
    ]
  end
end
