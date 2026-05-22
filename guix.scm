; SPDX-License-Identifier: MPL-2.0
;; guix.scm — GNU Guix package definition for BowtieRisk.jl
;; Usage: guix shell -f guix.scm

(use-modules (guix packages)
             (guix build-system gnu)
             (guix licenses))

(package
  (name "BowtieRisk.jl")
  (version "0.1.0")
  (source #f)
  (build-system gnu-build-system)
  (synopsis "BowtieRisk.jl")
  (description "BowtieRisk.jl — part of the hyperpolymath ecosystem.")
  (home-page "https://github.com/hyperpolymath/BowtieRisk.jl")
  (license ((@@ (guix licenses) license) "MPL-2.0"
             "https://github.com/hyperpolymath/palimpsest-license")))
