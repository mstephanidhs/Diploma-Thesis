# first monitor changes to the specified folder
python ./encryption/watch.py

# run all the services
docker-compose up

# start the client in order to retrieve the seismic data
python client.py