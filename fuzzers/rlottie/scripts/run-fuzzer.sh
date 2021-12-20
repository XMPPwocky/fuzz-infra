RSRC="@fuzz_resources_dir@"
@afl_path@/bin/afl-fuzz -m 512 -i $RSRC/corpus_small -x $RSRC/dictionary.txt -o /fuzz/afl "$@" -- harness-instrumented-hardened \@\@
