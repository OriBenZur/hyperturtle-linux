FROM alpine:latest AS build
RUN apk add --no-cache g++ musl-dev make
WORKDIR /app
COPY . .
RUN make

FROM alpine:latest
RUN apk add --no-cache musl-dev libstdc++ libgomp
WORKDIR /app
COPY --from=build /app/bc .
COPY --from=build /app/bfs .
COPY --from=build /app/cc .
COPY --from=build /app/cc_sv .
COPY --from=build /app/converter .
COPY --from=build /app/pr .
COPY --from=build /app/pr_spmv .
COPY --from=build /app/sssp .
COPY --from=build /app/tc .