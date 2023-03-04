#!/bin/sh

# plain:    hello
# key:      ABCD       (first 4 bytes in ./test_data/test.txt file
# cipher:   )'/(*L
export OUTPUT=`echo "hello" | ./bin/otp ./test/test_data/test.txt`
export EXPECTED_OUTPUT=")'/(*L"
export EXPECTED_NEXT_KEY="GH"

export NOW=`date +"%Y-%m-%d_%H:%M:%S"`
if test -f "./test/test_data/test.txt.$NOW.next"; then
  echo "   - PASS - next key file was created"
  next_key_file_ontent=`cat ./test/test_data/test.txt.$NOW.next`
else
  echo "   - FAIL - next key file was NOT created!"
  exit -1
fi


export NEXT_KEY=`cat ./test/test_data/test.txt.$NOW.next`
if [[ "$NEXT_KEY" = "$EXPECTED_NEXT_KEY" ]]; then
  echo "   - PASS - next key file has correct key (content)"
else
  echo "   - FAIL - next key file has WRONG key (content), expected '$EXPECTED_NEXT_KEY' but got '$NEXT_KEY'"
  exit -1
fi

if [[ "$OUTPUT" = "$EXPECTED_OUTPUT" ]]; then
  echo "   - PASS - output is correct"
  rm ./test/test_data/test.txt.$NOW.next
  exit 0
else
  echo "   - FAILED! Expected $EXPECTED_OUTPUT but got $OUTPUT"
fi

exit -1
