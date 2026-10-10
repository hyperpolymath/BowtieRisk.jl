# TEMPORARY (#61): formats src/ and test/ in place with JuliaFormatter.
using Pkg
Pkg.activate(mktempdir())
Pkg.add("JuliaFormatter")
using JuliaFormatter

files = String[]
for dir in ("src", "test")
    for (root, _, names) in walkdir(dir)
        for n in names
            endswith(n, ".jl") && push!(files, joinpath(root, n))
        end
    end
end
for f in sort(files)
    changed = format_file(f)
    println(changed ? "formatted " : "ok        ", f)
end
