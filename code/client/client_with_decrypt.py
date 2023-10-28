
from obspy.clients.seedlink.easyseedlink import EasySeedLinkClient

# Subclass the client class


class MyClient(EasySeedLinkClient):
    # Implement the on_data callback
    def on_data(self, trace):
        # trace should be decrypted here before print
        print('Received trace:')
        print(trace)


# Connect to a SeedLink server
client = MyClient('localhost:18000')
print("connected successfully")

# Retrieve INFO:STREAMS
streams_xml = client.get_info('STREAMS')
print(streams_xml)

# Select a stream and start receiving data
client.select_stream('ZW', 'ITSC', 'EHE')
client.run()


# rtserve.iris.washington.edu
