FROM gcr.io/oss-fuzz-base/base-builder@sha256:14b332de0e18683f37386eaedbf735bc6e8d81f9c0e1138d620f2178e20cd30a
COPY . $SRC/systemd
WORKDIR $SRC/systemd
COPY tools/oss-fuzz.sh $SRC/build.sh
