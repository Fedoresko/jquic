#!/bin/sh
service vsftpd start
ulimit -l unlimited

echo "Starting compiled BPF C program with root privileges..."
chmod +x /app/loader
strace -e bpf /app/loader &&

# Start the Java application in the background and capture its PID
su - fedoresko -c "cd /app && ${JAVA_HOME}/bin/java -XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints -Djava.net.preferIPv4Stack=true\
   --add-opens java.base/sun.nio.ch=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED --enable-native-access=ALL-UNNAMED -Dlog.level=WARN\
   -agentpath:/opt/async-profiler/lib/libasyncProfiler.so=start,event=cpu,event=alloc,event=nativemem,alloc=2m,loop=1m,file=/home/fedoresko/profile-%t.jfr\
   -jar jquic.jar" &
JAVA_PID=$!

# Launch the looping profiler script as a parallel background task
echo "Waiting 5 seconds for Java app to warm up..."
sleep 5

# Loop infinitely as long as the Java process remains active
while (true) do
  sleep 5
  find /home/fedoresko -type f -name "*.jfr" -printf "%T@ %p\n" | \
                                                sort -rn | \
                                                awk '{sub(/^[^ ]+ /, ""); print}' | \
                                                tail -n +2 | while read -r FILE; do
      echo "Processing: $FILE"
      BASE_NAME="${FILE%.*}"
      OUTPUT_FILE="${BASE_NAME}.html"
      DIR=$(dirname "$OUTPUT_FILE")
      BASE=$(basename "$OUTPUT_FILE")
      /opt/async-profiler/bin/jfrconv -o heatmap "$FILE" "$DIR/cpu-$BASE"
      /opt/async-profiler/bin/jfrconv --alloc --total -o heatmap "$FILE" "$DIR/mem-$BASE"
      /opt/async-profiler/bin/jfrconv --nativemem --total -o heatmap "$FILE" "$DIR/nmem-$BASE"
      if [ $? -eq 0 ]; then
          echo "Success. Deleting original file..."
          rm "$FILE"
      else
          echo "Error: Conversion failed for $FILE. Keeping original file."
      fi
  done
done
# Keep the Docker container running by tying it to the main Java process