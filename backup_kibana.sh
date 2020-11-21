for type in visualization dashboard index-pattern
do
    curl -X POST -H 'kbn-xsrf: true' \
        -H 'Content-Type: application/json' \
        -d "{\"type\":\"$type\"}" \
        localhost:5601/api/saved_objects/_export  > kibana_${type}.json
done

docker run -v $(pwd):/application -w /application -it node npm install elasticdump
docker run -v $(pwd):/application -w /application -it node node_modules/elasticdump/bin/elasticdump \
    --input=http://192.168.3.170:9200/.kibana_1 \
    --output=\$ | gzip > kibana.json.gz