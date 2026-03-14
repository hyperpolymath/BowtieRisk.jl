# SPDX-License-Identifier: MPL-2.0
# (PMPL-1.0-or-later preferred; MPL-2.0 required for Julia ecosystem)
using Documenter
using BowtieRisk

makedocs(
    sitename = "BowtieRisk.jl",
    format = Documenter.HTML(
        prettyurls = get(ENV, "CI", nothing) == "true",
        canonical = "https://hyperpolymath.github.io/BowtieRisk.jl",
    ),
    modules = [BowtieRisk],
    pages = ["Home" => "index.md", "API" => "api.md"],
)

deploydocs(
    repo = "github.com/hyperpolymath/BowtieRisk.jl.git",
    devbranch = "main",
)
