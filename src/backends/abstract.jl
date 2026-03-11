# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRisk.jl Backend Abstraction
# Uses AcceleratorGate.jl for shared coprocessor dispatch infrastructure.

using AcceleratorGate
using AcceleratorGate: generate_self_healing_hooks

# ============================================================================
# Domain-Specific Operation Hooks -- BowtieRisk
# ============================================================================

# Julia fallback implementations
backend_monte_carlo_step(::JuliaBackend, args...) = nothing
backend_risk_aggregate(::JuliaBackend, args...) = nothing
backend_barrier_eval(::JuliaBackend, args...) = nothing
backend_correlation_matrix(::JuliaBackend, args...) = nothing
backend_probability_sample(::JuliaBackend, args...) = nothing

# Coprocessor extension hooks (concrete extensions overload these)
function backend_coprocessor_monte_carlo_step end
function backend_coprocessor_risk_aggregate end
function backend_coprocessor_barrier_eval end
function backend_coprocessor_correlation_matrix end
function backend_coprocessor_probability_sample end

# Self-healing fallback generation for coprocessor hooks
generate_self_healing_hooks(@__MODULE__, [
    (:backend_coprocessor_monte_carlo_step, :backend_monte_carlo_step),
    (:backend_coprocessor_risk_aggregate, :backend_risk_aggregate),
    (:backend_coprocessor_barrier_eval, :backend_barrier_eval),
    (:backend_coprocessor_correlation_matrix, :backend_correlation_matrix),
    (:backend_coprocessor_probability_sample, :backend_probability_sample),
])

# Dispatch: CoprocessorBackend -> coprocessor hook
backend_monte_carlo_step(b::CoprocessorBackend, args...) = backend_coprocessor_monte_carlo_step(b, args...)
backend_risk_aggregate(b::CoprocessorBackend, args...) = backend_coprocessor_risk_aggregate(b, args...)
backend_barrier_eval(b::CoprocessorBackend, args...) = backend_coprocessor_barrier_eval(b, args...)
backend_correlation_matrix(b::CoprocessorBackend, args...) = backend_coprocessor_correlation_matrix(b, args...)
backend_probability_sample(b::CoprocessorBackend, args...) = backend_coprocessor_probability_sample(b, args...)

# Dispatch: GPUBackend -> Julia fallback (extensions override)
backend_monte_carlo_step(b::GPUBackend, args...) = backend_monte_carlo_step(JuliaBackend(), args...)
backend_risk_aggregate(b::GPUBackend, args...) = backend_risk_aggregate(JuliaBackend(), args...)
backend_barrier_eval(b::GPUBackend, args...) = backend_barrier_eval(JuliaBackend(), args...)
backend_correlation_matrix(b::GPUBackend, args...) = backend_correlation_matrix(JuliaBackend(), args...)
backend_probability_sample(b::GPUBackend, args...) = backend_probability_sample(JuliaBackend(), args...)
