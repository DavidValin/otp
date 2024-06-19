#!/bin/sh

# plain:              16ag
# key:                abcdefghijklmn   (first 4 bytes in ./test_data/test.txt file)
# expected cipher:    PT
# expected next key:  efghijklmn       (last 4 bytes in ./test_data/test.txt file)
export PLAIN='16ag'
export OUTPUT=`echo -n $PLAIN | ./bin/otp ./test/test_data/test.txt`
export EXPECTED_OUTPUT='PT'
export EXPECTED_NEXT_KEY="efghijklmn"
export NOW=`date +"%Y-%m-%d_%H:%M:%S"`

if [[ "$OUTPUT" = "$EXPECTED_OUTPUT" ]]; then
  echo "   - PASS - output is correct"
else
  echo "   ! FAIL : Expected $EXPECTED_OUTPUT but got $OUTPUT"
  exit -1
fi

if test -f "./test/test_data/test.txt.$NOW.next"; then
  echo "   - PASS - next key file was created"
else
  echo "   - FAIL : next key file was NOT created!"
  exit -1
fi

export NEXT_KEY=`cat ./test/test_data/test.txt.$NOW.next`
if [[ "$NEXT_KEY" = "$EXPECTED_NEXT_KEY" ]]; then
  echo "   - PASS - next key file has correct key (content)"
else
  echo "   ! FAIL : next key file has WRONG key (content), expected '$EXPECTED_NEXT_KEY' but got '$NEXT_KEY'"
  exit -1
fi

rm ./test/test_data/test.txt.$NOW.next

export ORIGINAL=`echo -n $OUTPUT | ./bin/otp ./test/test_data/test.txt`
if [[ "$ORIGINAL" = "$PLAIN" ]]; then
  echo "   - PASS - decryption (content) is correct"
else
  echo "   ! FAIL : decryption (content) is incorrect, expected '$PLAIN' but got '$ORIGINAL'"
  exit -1
fi


exit 0
