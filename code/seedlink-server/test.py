from obspy import read


t1 = read('.\\archive\\2023\\HP\\UPR\\HHZ.D\\HP.UPR..HHZ.D.2023.319', format='MSEED')

t2 = read('.\\..\\slarchive-server\\archive\\2023\\HP\\UPR\\HHZ.D\\HP.UPR..HHZ.D.2023.319', format='MSEED')

s = t1 + t2
s.plot()
