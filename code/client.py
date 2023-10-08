from obspy.clients.seedlink.easyseedlink import EasySeedLinkClient
from obspy.core.trace import Trace
from obspy.core.stream import Stream

import sys

i = 1  # used as an index for each trace received from the server
stream = Stream()


class MyClient(EasySeedLinkClient):

    def __init__(self, server_url, autoconnect=True, print_streams=False):
        super().__init__(server_url, autoconnect)

        self.selected_stream = []

        # Retrieve INFO:STREAMS
        if print_streams == True:
            self.stream_xml = self.get_info('STREAMS')
            print(self.stream_xml)

    # add stream to be processed
    def add_stream(self, net, sta, cha):
        # Select a stream and start receiving data
        self.select_stream(net, sta, cha)
        stream = '.'.join([net, sta, cha])
        self.selected_stream.append(stream)
        print("Stream %s added." % stream)

    def print_selected_streams(self):
        for stream in self.selected_stream:
            print("Stream: %s" % stream)

    # Implement the on_data callback
    def on_data(self, trace):
        global i
        global traces

        if i == 1:
            print("Received Traces.")
            traces = Trace()  # create a new blank trace to write to
            traces = trace
            print('Trace %s: %s' % (i, trace))
        else:
            print('Trace %s: %s' % (i, trace))
            traces += trace
            traces.__add__(trace)

            if i == 2:
                print("Saving %s traces..." % i)
                print("Done.")
                stream.append(traces)
                self.stop_seedlink()

        i += 1

    def stop_seedlink(self):
        self.conn.close()
        sys.exit(0)


if __name__ == '__main__':

    seedlink_server = 'rtserve.iris.washington.edu'
    seedlink_port = '18000'

    # forge seedlink url in order to have address:port format
    seedlink_url = ':'.join([seedlink_server, seedlink_port])

    # net = 'NE'  # network code
    # sta = 'WES'  # station name
    # cha = 'HHZ'  # channel
    net = 'ZW'  # network code
    sta = 'ITSC'  # station name
    cha = 'EHZ'  # channel

    # Connect to a Seedlink server
    client = MyClient(seedlink_url)
    client.add_stream(net, sta, cha)
    client.run()
