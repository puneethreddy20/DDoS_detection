from django.shortcuts import render,render_to_response
from django.http import HttpResponse,HttpResponseRedirect
from django.template import loader
import dpkt
import socket


# Create your views here.
def index(request):
    #template=loader.get_template('Home/index.html')
    #return HttpResponse(template.render(request,'index.html'))
    return render(request,'Home/index.html',context=None)

def loic(request):
    #template=loader.get_template('Home/LOIC-download-Detection.html')
    #return render_to_response(template, request, context=None)
    #return render_to_response(request, 'Home/LOIC-download-Detection.html', context=None)

    return render(request, 'Home/LOIC-download-Detection.html', context=None)

def irc(request):
    return render(request, 'Home/DDoS-IRC.html', context=None)

def attack(request):
    return render(request, 'Home/Attack-Detection.html', context=None)


def postsubmit(request):
    sourceaddress=[]
    if request.method == 'POST':
        pcap = dpkt.pcap.Reader(request.FILES['loicfile'])
        findDownload(pcap,sourceaddress)
        print(sourceaddress)
        return render(request, 'Home/result.html', context={'sourceaddress':sourceaddress})

    return render(request, 'Home/result.html', context={'sourceaddress': sourceaddress})

def findDownload(pcap,sourceaddress):
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            tcp = ip.data
            http = dpkt.http.Request(tcp.data)
            if http.method == 'GET':
                uri = http.uri.lower()
            if '.zip' in uri and 'loic' in uri:
                print('[!]'  + src +    ' Downloaded LOIC')
                if src not in sourceaddress:
                    sourceaddress.append(src)
            else:
                print("Loic toolkit is not downloaded")
        except:
            pass
    return sourceaddress




def postsubmithivemind(request):
    sourceaddressHive = []
    tcpdata = []
    sourceaddress2list = []
    tcpdata2list = []
    if request.method == 'POST':
        pcap = dpkt.pcap.Reader(request.FILES['hivemind'])
        findHivemind(pcap,sourceaddressHive,tcpdata,sourceaddress2list,tcpdata2list)
        print(tcpdata)
        print(sourceaddressHive)
        print(sourceaddress2list)
        print(tcpdata2list)
        return render(request, 'Home/ircresult.html', context={'sourceaddressHive':sourceaddressHive,'tcpdata':tcpdata,'sourceaddress2list':sourceaddress2list,'tcpdata2list':tcpdata2list})

    return render(request, 'Home/ircresult.html', context={'sourceaddressHive': sourceaddressHive, 'tcpdata': tcpdata, 'sourceaddress2list': sourceaddress2list, 'tcpdata2list': tcpdata2list})


def findHivemind(pcap,sourceaddressHive,tcpdata,sourceaddress2list,tcpdata2list):
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dport = tcp.dport
            sport = tcp.sport
            if dport == 6667:

                if '!lazor' in str(tcp.data.lower()):
                    print('[!] DDoS Hivemind issued by: '+src)
                    print ('[+] Target CMD: ' + str(tcp.data))
                    sourceaddressHive.append(src)
                    tcpdata.append(tcp.data)
            if sport == 6667:
                if '!lazor' in str(tcp.data.lower()):
                    print ('[!] DDoS Hivemind issued to: '+src)
                    print ('[+] Target CMD: ' + str(tcp.data))
                    sourceaddress2list.append(src)
                    tcpdata2list.append(tcp.data)
        except Exception as e:
            print(e)





def postsubmitattack(request):
    source = []
    destination = []
    packetssent = []
    if request.method == 'POST':
        pcap = dpkt.pcap.Reader(request.FILES['thresholdfile'])
        findAttack(pcap,source,destination,packetssent)
        print(source)
        return render(request, 'Home/attackresult.html', context={'source':source,'destination':destination,'packetssent':packetssent})

    return render(request, 'Home/attackresult.html',context={'source': source, 'destination': destination, 'packetssent': packetssent})


def findAttack(pcap,source,destination,packetssent):
    THRESH = 10000
    pktCount = {}

    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dport = tcp.dport
            if dport == 80:
                stream = src + ':' + dst
                if stream in pktCount:
                    pktCount[stream] = pktCount[stream] + 1
                else:
                    pktCount[stream] = 1

        except Exception as e:
            print(e)
    print(pktCount)
    for stream in pktCount:
        pktsSent = pktCount[stream]
        if pktsSent > THRESH:
            src = stream.split(':')[0]
            dst = stream.split(':')[1]
            print ('[+] '+src+' attacked '+dst+' with ' + str(pktsSent) + ' pkts.')
            source.append(src)
            destination.append(dst)
            packetssent.append(pktsSent)
            print(source)
            print(destination)
            print(packetssent)
    return source,destination,packetssent