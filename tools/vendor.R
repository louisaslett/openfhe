#!/usr/bin/env Rscript

# tools/vendor.R -- (re)produce src/vendor/ from pinned upstream sources.
#
# MAINTAINER USE ONLY.  This script never runs at package install time.
#
# What it does:
#   1. Copies a trimmed OpenFHE tree (core/pke/binfhe, lib + include only,
#      excluding the NTL math backend sources) into src/vendor/.
#   2. Clones the cereal serialization headers (OpenFHE's fork) at a pinned
#      commit into src/vendor/cereal/include/cereal.
#   3. Writes the static src/vendor/config_core.h (replaces CMake's
#      configure_file; see comments in that header).
#   4. Rewrites std::cout / std::cerr throughout the vendored tree to the
#      R-safe lbcrypto::RCout / lbcrypto::RCerr (src/r_shim/), and strips
#      all '#pragma (GCC|clang) diagnostic ignored' lines (R CMD check
#      flags diagnostic-suppressing pragmas, and treats some, e.g.
#      -Wclass-memaccess, as non-portable -> WARNING).  The full diff is
#      recorded in tools/patches/0001-cran-compliance.patch.
#   5. Regenerates the OBJECTS lists in src/Makevars and src/Makevars.win.
#   6. Records upstream provenance and per-file MD5 checksums in
#      tools/VENDOR_MANIFEST.
#
# Usage (from the package root):
#   Rscript tools/vendor.R [path-to-openfhe-development-checkout]
#
# The OpenFHE source defaults to ../openfhe-development relative to the
# package root.  Network access is required to clone cereal.

OPENFHE_VERSION <- "1.5.1"
CEREAL_REPO     <- "https://github.com/openfheorg/cereal"
# Pinned cereal commit; "" means use HEAD of the default branch and report
# the SHA so it can be pinned here.
CEREAL_COMMIT   <- "984e3f194862b17916536b5fade40cba6e47a6fe"

modules <- c("core", "pke", "binfhe")

fail <- function(...) stop(sprintf(...), call. = FALSE)

# --- locate directories ------------------------------------------------------
if (!file.exists("DESCRIPTION") ||
    !any(grepl("^Package: openfhe", readLines("DESCRIPTION")))) {
  fail("run this script from the openfhe package root: Rscript tools/vendor.R")
}
pkg_root <- normalizePath(".")

args <- commandArgs(trailingOnly = TRUE)
upstream <- if (length(args) >= 1) args[[1]] else file.path("..", "openfhe-development")
upstream <- normalizePath(upstream, mustWork = FALSE)
if (!dir.exists(file.path(upstream, "src", "pke"))) {
  fail("OpenFHE source tree not found at '%s'", upstream)
}

# verify upstream version
cml <- readLines(file.path(upstream, "CMakeLists.txt"), warn = FALSE)
ver <- paste(
  sub(".*OPENFHE_VERSION_MAJOR *([0-9]+).*", "\\1", grep("set *\\( *OPENFHE_VERSION_MAJOR", cml, value = TRUE)[1]),
  sub(".*OPENFHE_VERSION_MINOR *([0-9]+).*", "\\1", grep("set *\\( *OPENFHE_VERSION_MINOR", cml, value = TRUE)[1]),
  sub(".*OPENFHE_VERSION_PATCH *([0-9]+).*", "\\1", grep("set *\\( *OPENFHE_VERSION_PATCH", cml, value = TRUE)[1]),
  sep = "."
)
if (!identical(ver, OPENFHE_VERSION)) {
  fail("upstream at '%s' is version %s but this script expects %s (update OPENFHE_VERSION and review patches)",
       upstream, ver, OPENFHE_VERSION)
}
message("Vendoring OpenFHE ", ver, " from ", upstream)

vendor <- file.path(pkg_root, "src", "vendor")
unlink(vendor, recursive = TRUE)
dir.create(vendor, recursive = TRUE)

# --- 1. copy trimmed OpenFHE tree -------------------------------------------
copy_tree <- function(from, to) {
  files <- list.files(from, recursive = TRUE, all.files = FALSE, full.names = FALSE)
  for (f in files) {
    dest <- file.path(to, f)
    dir.create(dirname(dest), recursive = TRUE, showWarnings = FALSE)
    if (!file.copy(file.path(from, f), dest, copy.date = TRUE)) {
      fail("failed to copy %s", file.path(from, f))
    }
  }
  invisible(length(files))
}

for (m in modules) {
  for (part in c("lib", "include")) {
    n <- copy_tree(file.path(upstream, "src", m, part), file.path(vendor, m, part))
    message(sprintf("  %-6s %-7s : %4d files", m, part, n))
  }
}

# drop the NTL math backend sources (WITH_NTL is off; TUs are #ifdef-guarded
# but excluding them also removes their std::cout/std::cerr sites and weight).
unlink(file.path(vendor, "core", "lib", "math", "hal", "bigintntl"), recursive = TRUE)

# --- 2. cereal headers -------------------------------------------------------
tmp <- tempfile("cereal-")
message("Cloning cereal from ", CEREAL_REPO)
if (system2("git", c("clone", "--quiet", CEREAL_REPO, shQuote(tmp))) != 0L) {
  fail("git clone of cereal failed")
}
if (nzchar(CEREAL_COMMIT)) {
  if (system2("git", c("-C", shQuote(tmp), "checkout", "--quiet", CEREAL_COMMIT)) != 0L) {
    fail("could not check out pinned cereal commit %s", CEREAL_COMMIT)
  }
}
cereal_sha <- system2("git", c("-C", shQuote(tmp), "rev-parse", "HEAD"), stdout = TRUE)
message("cereal at commit ", cereal_sha)
copy_tree(file.path(tmp, "include", "cereal"),
          file.path(vendor, "cereal", "include", "cereal"))
unlink(tmp, recursive = TRUE)

# --- 3. static config_core.h -------------------------------------------------
writeLines(c(
  "// Static replacement for the CMake-generated config_core.h",
  "// (template: configure/config_core.in in the OpenFHE sources).",
  "// Written by tools/vendor.R for the openfhe R package build:",
  "//  * fixed choices: math backend 4 (no NTL/GMP), 64-bit native ints,",
  "//    no tcmalloc, no noise debug, CKKS_M_FACTOR 1",
  "//  * HAVE_INT128 keyed off the compiler (gcc/clang define",
  "//    __SIZEOF_INT128__ on all 64-bit CRAN platforms; OpenFHE has a",
  "//    portable fallback path when it is absent)",
  "//  * OpenMP keyed off _OPENMP, which is set exactly when R's",
  "//    $(SHLIB_OPENMP_CXXFLAGS) is active (see src/Makevars)",
  "#ifndef __CMAKE_GENERATED_CONFIG_CORE_H__",
  "#define __CMAKE_GENERATED_CONFIG_CORE_H__",
  "",
  "#define WITH_BE4",
  "#define MATHBACKEND 4",
  "#define NATIVEINT 64",
  "#define HAVE_INT64 1",
  "#define CKKS_M_FACTOR 1",
  "",
  "#if defined(__SIZEOF_INT128__)",
  "    #define HAVE_INT128 1",
  "#endif",
  "",
  "#ifdef _OPENMP",
  "    #define WITH_OPENMP",
  "    #define PARALLEL",
  "#endif",
  "",
  "#endif  // __CMAKE_GENERATED_CONFIG_CORE_H__"
), file.path(vendor, "config_core.h"))

# --- 4. CRAN compliance patch ------------------------------------------------
# (a) CRAN: "Compiled code should not ... write to stdout/stderr".  Replace
#     every std::cout / std::cerr in the vendored tree (cereal included,
#     defensively) with the R-safe streams from src/r_shim/r_stream.h.
# (b) R CMD check's pragma scan (tools:::.check_pragmas) flags any
#     '#pragma (GCC|clang) diagnostic ignored' as diagnostic suppression and
#     some suppressed warnings as non-portable => WARNING under --as-cran.
#     Strip those lines; the surrounding push/pop pairs remain and are
#     harmless no-ops.  The compiler warnings this re-exposes are acceptable
#     (CRAN forbids suppressing them anyway).
pristine <- file.path(tempdir(), "vendor-pristine")
unlink(pristine, recursive = TRUE)
dir.create(pristine, recursive = TRUE)
copy_tree(vendor, pristine)

src_files <- list.files(vendor, pattern = "\\.(h|hpp|c|cpp)$",
                        recursive = TRUE, full.names = TRUE)
pragma_re <- "^\\s*#\\s*pragma\\s+(GCC|clang)\\s+diagnostic\\s+ignored"
patched <- pragma_stripped <- character()
for (f in src_files) {
  txt <- readLines(f, warn = FALSE)
  rel <- sub(paste0(vendor, "/"), "", f)
  changed <- FALSE
  if (any(grepl("std::(cout|cerr)", txt))) {
    txt <- gsub("std::cout", "lbcrypto::RCout", txt, fixed = TRUE)
    txt <- gsub("std::cerr", "lbcrypto::RCerr", txt, fixed = TRUE)
    txt <- c("#include \"r_shim/r_stream.h\"  // openfhe R package patch", txt)
    patched <- c(patched, rel)
    changed <- TRUE
  }
  if (any(grepl(pragma_re, txt, perl = TRUE))) {
    txt <- txt[!grepl(pragma_re, txt, perl = TRUE)]
    pragma_stripped <- c(pragma_stripped, rel)
    changed <- TRUE
  }
  if (changed) writeLines(txt, f)
}
message("iostream patch applied to ", length(patched), " files:")
message(paste("  ", patched, collapse = "\n"))
message("diagnostic-ignored pragmas stripped from ", length(pragma_stripped), " files:")
message(paste("  ", pragma_stripped, collapse = "\n"))

# the seven compiled TUs known to need the patch must all be present
expected <- c(
  "core/lib/utils/blockAllocator/xallocator.cpp",
  "core/lib/utils/prng/blake2engine.cpp",
  "core/lib/math/dftransform.cpp",
  "core/lib/math/distributiongenerator.cpp",
  "core/lib/math/hal/bigintdyn/ubintdyn.cpp",
  "pke/lib/scheme/ckksrns/ckksrns-fhe.cpp",
  "binfhe/lib/lwe-pke.cpp"
)
missing <- setdiff(expected, patched)
if (length(missing)) {
  fail("expected to patch these compiled files but did not:\n%s",
       paste(" ", missing, collapse = "\n"))
}

# record the patch as a reviewable diff
dir.create(file.path(pkg_root, "tools", "patches"), showWarnings = FALSE, recursive = TRUE)
patch_file <- file.path(pkg_root, "tools", "patches", "0001-cran-compliance.patch")
diff_out <- suppressWarnings(
  system2("diff", c("-ruN", shQuote(pristine), shQuote(vendor)), stdout = TRUE)
)
diff_out <- gsub(pristine, "a/src/vendor", diff_out, fixed = TRUE)
diff_out <- gsub(vendor,   "b/src/vendor", diff_out, fixed = TRUE)
writeLines(diff_out, patch_file)
unlink(pristine, recursive = TRUE)
message("patch diff written to ", patch_file)

# --- 5. regenerate OBJECTS in Makevars / Makevars.win ------------------------
rel_src <- function(paths) sub(paste0(file.path(pkg_root, "src"), "/"), "", paths)

# Binding glue at the top of src/ is picked up by a GNU-make wildcard so new
# glue files never require re-vendoring; only the vendored tree is explicit.
vendor_srcs <- list.files(vendor, pattern = "\\.(cpp|c)$",
                          recursive = TRUE, full.names = TRUE)
objs <- sub("\\.(cpp|c)$", ".o", rel_src(sort(vendor_srcs)))
obj_lines <- paste0(
  "OBJECTS = $(patsubst %.cpp,%.o,$(wildcard *.cpp)) r_shim/r_stream.o \\\n\t",
  paste(objs, collapse = " \\\n\t")
)

for (mk in c("Makevars", "Makevars.win")) {
  path <- file.path(pkg_root, "src", mk)
  txt <- readLines(path)
  beg <- grep("^# vvv OBJECTS generated", txt)
  end <- grep("^# \\^\\^\\^ OBJECTS generated", txt)
  if (length(beg) != 1L || length(end) != 1L || end <= beg) {
    fail("OBJECTS markers not found in src/%s", mk)
  }
  txt <- c(txt[seq_len(beg)], obj_lines, txt[end:length(txt)])
  writeLines(txt, path)
  message("OBJECTS list (", length(objs), " objects) written to src/", mk)
}

# --- 6. manifest -------------------------------------------------------------
vend_files <- sort(list.files(vendor, recursive = TRUE))
sums <- tools::md5sum(file.path(vendor, vend_files))
writeLines(c(
  "# Provenance of src/vendor/ -- generated by tools/vendor.R; do not edit.",
  paste0("openfhe_version: ", OPENFHE_VERSION),
  paste0("openfhe_source: https://github.com/openfheorg/openfhe-development (tag v", OPENFHE_VERSION, ")"),
  paste0("cereal_source: ", CEREAL_REPO),
  paste0("cereal_commit: ", cereal_sha),
  paste0("patches: ", "tools/patches/0001-cran-compliance.patch"),
  paste0("generated: ", format(Sys.time(), tz = "UTC", usetz = TRUE)),
  "",
  "# md5  file",
  paste(unname(sums), vend_files)
), file.path(pkg_root, "tools", "VENDOR_MANIFEST"))
message("manifest written to tools/VENDOR_MANIFEST")

message("Done.  Vendored ", length(vend_files), " files, ",
        length(objs), " objects to compile.")
