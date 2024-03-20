from obspy import read


t1 = read('.\\archive\\2023\\HP\\UPR\\HHN.D\\HP.UPR..HHN.D.2023.345', format='MSEED')

t2 = read('.\\..\\seismograph\\archive\\2023\\HP\\UPR\\HHN.D\\HP.UPR..HHN.D.2023.338', format='MSEED')

s = t1 + t2
s.plot()
