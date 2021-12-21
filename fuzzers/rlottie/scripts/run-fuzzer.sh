RSRC="@fuzz_resources_dir@"
@afl_path@/bin/afl-fuzz -i $RSRC/corpus_small -x $RSRC/dictionary.txt "$@" -- @harness@
