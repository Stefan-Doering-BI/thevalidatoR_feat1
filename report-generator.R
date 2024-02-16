#Add libraries 
library(magrittr)

#!/usr/bin/env Rscript

# Location
cat(sprintf("Current dir is: '%s'", getwd()))

# CVE-2022-24765 exception
git_safe_dir <- system(
  sprintf("git config --global --add safe.directory '%s'", getwd())
)

# Get the action inputs from preset env vars
pkg_dir <- normalizePath(Sys.getenv("INPUT_REPORT_PKG_DIR", "."))
report_output_prefix <- Sys.getenv("INPUT_REPORT_OUTPUT_PREFIX", "")
disable_install_dev_deps <- tolower(
  Sys.getenv("DISABLE_INSTALL_DEV_DEPS")
) %in% c("yes", "y", "t", "true")

# fail with meaningful message if REPORT_PKG_DIR does not appear to be a package
desc_file <- file.path(pkg_dir, "DESCRIPTION")
if (!file.exists(desc_file)) {
  stop(sprintf(
    paste(sep = "\n",
      "Could not find package at '%s'",
      "    ",
      "    Specify a directory by definining environment variable:",
      "        INPUT_REPORT_PKG_DIR=<repository subdirectory>",
      "    "
    ),
    pkg_dir
  ))
}

# Install package dependencies
if (!disable_install_dev_deps) {
    options("remotes.git_credentials" = git2r::cred_user_pass(
        username = "token",
        password = remotes:::github_pat()
    ))
    devtools::install_dev_deps(pkg_dir, upgrade = "never")
}

# find .git dir containing the package directory
gd <- system(
  sprintf("cd '%s' && git rev-parse --absolute-git-dir", pkg_dir),
  intern = TRUE
)
# define reused git args to be sure we're picking up the right git info
gd <- sprintf("--git-dir='%s'", gd)
wt <- sprintf("--work-tree='%s'", pkg_dir)

#riskmetric
d_riskmetric <- pkg_dir %>%
  riskmetric::pkg_ref() %>%
  riskmetric::pkg_assess() %>%
  purrr::map(1) %>%
  lapply(as.character) %>%
  tibble::enframe() %>%
  tidyr::unnest(cols = dplyr::everything()) %>%
  # add labels
  dplyr::left_join(
    lapply(riskmetric::all_assessments(), attributes) %>%
      purrr::map_df(tibble::as_tibble),
    by = c("name" = "column_name")
  )


validation_report_json <- data.frame(
  Field = c("document_typ","package_name","version", "repository", "commit_sha", "github_reference", "branch", "commit_date", "OS", "Platform", "System", "Execution Time"),
  Value = c("val_rep_json", #document_typ
            read.dcf(desc_file)[,'Package'], #package_name
            read.dcf(desc_file)[,'Version'], #version
            Sys.getenv('GITHUB_REPOSITORY'), #repository
            Sys.getenv('GITHUB_SHA'), #commit_sha
            Sys.getenv('GITHUB_REF'), #github_reference
            system2( #branch
              "git",
              list(gd, wt, "rev-parse", "--abbrev-ref", "HEAD"),
              stdout = TRUE
            ),
            system2( #commit_date
              "git",
              list(gd, wt, "show", "-s", "--format=%ci", "HEAD"),
              stdout = TRUE
            ),
            sessionInfo()$running, #OS
            R.version$platform, #Platform
            R.version$system, #System
            format(Sys.time(), tz = "UTC", usetz = TRUE) #Execution Time
  ))

validation_report_json <- dplyr::bind_rows(
  validation_report_json,
  d_riskmetric %>%
    dplyr::filter(
      name %in% c(
        "news_current", "has_vignettes",
        "license", "downloads_1yr"
      )
    ) %>%
    dplyr::rename(Field = name, Value= value) %>%
    dplyr::select(Field, Value)
)

rcmdcheck_results <- rcmdcheck::rcmdcheck(
  pkg_dir,
  args = c(
    "--timings",             # include execution times in output
    "--no-build-vignettes",  # run vignette code, but disable pdf rendering
    "--no-manual"            # disable pdf manual rendering
  ),
  quiet = TRUE
)

validation_report_json <- dplyr::bind_rows(
  validation_report_json,
  data.frame(
    Field = c("rcmdcheck stdout", "rcmdcheck stderr"),
    Value = c(rcmdcheck_results$stdout, rcmdcheck_results$stderr),
    stringsAsFactors = FALSE
  )
)

## Testing Coverage

covr_results <- covr::package_coverage(pkg_dir)
covr_results

#creates json
json_object <- jsonlite::toJSON(validation_report_json, pretty = TRUE)

# Set the output file name
if (report_output_prefix == "") {
  desc <- read.dcf(desc_file)
  pkg_name <- toString(desc[, "Package"])
  pkg_version <- toString(desc[, "Version"])
  report_output_prefix <- paste0(
    pkg_name, "-", pkg_version, "-validation-report"
  )
}

report_file_path <- paste0(report_output_prefix,".json")

# Write the JSON object to a file
write(json_object, file = report_file_path)

# Create a tmp file which contains the final report filename
writeLines(report_file_path, "/tmp/report_file_path.txt")

cat(sprintf("Created report at: '%s'\n\n", report_file_path))
