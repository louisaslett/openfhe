// Static replacement for the CMake-generated config_core.h
// (template: configure/config_core.in in the OpenFHE sources).
// Written by tools/vendor.R for the openfhe R package build:
//  * fixed choices: math backend 4 (no NTL/GMP), 64-bit native ints,
//    no tcmalloc, no noise debug, CKKS_M_FACTOR 1
//  * HAVE_INT128 keyed off the compiler (gcc/clang define
//    __SIZEOF_INT128__ on all 64-bit CRAN platforms; OpenFHE has a
//    portable fallback path when it is absent)
//  * OpenMP keyed off _OPENMP, which is set exactly when R's
//    $(SHLIB_OPENMP_CXXFLAGS) is active (see src/Makevars)
#ifndef __CMAKE_GENERATED_CONFIG_CORE_H__
#define __CMAKE_GENERATED_CONFIG_CORE_H__

#define WITH_BE4
#define MATHBACKEND 4
#define NATIVEINT 64
#define HAVE_INT64 1
#define CKKS_M_FACTOR 1

#if defined(__SIZEOF_INT128__)
    #define HAVE_INT128 1
#endif

#ifdef _OPENMP
    #define WITH_OPENMP
    #define PARALLEL
#endif

#endif  // __CMAKE_GENERATED_CONFIG_CORE_H__
