import streamlit as st
import numpy as np
import os
import re
from PIL import Image
from datetime import datetime
import pytz
import time
import zipfile
import base64
import sys,os,hashlib,colorama
from colorama import Fore, Back, Style, init
init()
def parse_str(x):
    return x[1:-1]
def parse_datetime(x):
    dt = datetime.strptime(x[1:-7], '%d/%b/%Y:%H:%M:%S')
    dt_tz = int(x[-6:-3])*60+int(x[-3:-1])
    return dt.replace(tzinfo=pytz.FixedOffset(dt_tz))
def retrieve_file_paths(dirName):
    # setup file paths variable
    filePaths = []
    # Read all directory, subdirectories and file lists
    for root, directories, files in os.walk(dirName):
        for filename in files:
        # Create the full filepath by using os module.
            filePath = os.path.join(root, filename)
            filePaths.append(filePath)
    # return all paths
    return filePaths
def Freq_Counter(mylist, iplabel):
    freq = {}
    for item in mylist:
        if item in freq:
            freq[item] += 1
        else:
            freq[item] = 1
    max_freq = 0
    max_key = 0
    for key,value in freq.items():
        if value > max_freq:
            max_freq = value
            max_key = key
    return iplabel[mylist.index(max_key)]
def log(log_down):
    import pandas as pd
    import re
    ip = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
    status = re.compile(r" \b\d\d\d\b ")
    with log_down as file:
        ipList = []
        statusList = []
        for line in file.readlines():
            ipaddr = ip.findall(line)
            scode = status.findall(line)
            if ipaddr and scode:
                ipList.append(ipaddr[0])
                statusList.append(scode[0])
            else:
                pass
    col1 = pd.DataFrame(ipList, columns=['ClientIP'])
    col2 = pd.DataFrame(statusList, columns=['Status_code'])
    dataset = pd.concat([col1, col2], axis=1)
    dataset.to_csv('ip_set.csv', index=False)
    #######
    
    dataset = pd.read_csv('access_log',
    sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
    engine='python',
    na_values='-',
    header=None,
    usecols=[0, 3, 4, 5, 6, 7, 8],
    names=['ip', 'time', 'request', 'status', 'size', 'referer',
    'user_agent'],
    converters={'time': parse_datetime,
                'request': parse_str,
                'status': int,
                'size': int,
                'referer': parse_str,
                'user_agent': parse_str})
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    label = LabelEncoder()
    sc = StandardScaler()
    x =dataset
    X = x.to_numpy()
    ip = label.fit_transform(X[:,0])
    date = label.fit_transform(X[:,1])
  
    df_ip = pd.DataFrame(ip, columns = ['IP'])
    df_date = pd.DataFrame(date, columns = ['Date'])

    result = pd.concat([df_ip,df_date], axis = 1)
    data_scaled = sc.fit_transform(result)
    from sklearn.cluster import KMeans
    import matplotlib.pyplot as plt
    wcss =[]
    for i in range(1,4):
        model = KMeans(n_clusters = i)
        model.fit(data_scaled)
        st.write('model with ',i,' clusters created....')
        w = model.inertia_
        wcss.append(w)
    #plt.plot(range(1,11), wcss, marker = 'o')
    from sklearn.cluster import KMeans
    import plotly.figure_factory as ff
    from sklearn.metrics import accuracy_score
    model = KMeans(n_clusters = 6)
    model.fit(data_scaled)
    pred = model.fit_predict(data_scaled)
    print('Accuracy: {}'.format(model.predict(data_scaled)))
    dataset = pd.DataFrame(data_scaled, columns = ['IP','Date'])
    dataset['Cluster No'] = pred
    #st.line_chart(dataset)
    #fig = plt.scatter(dataset['IP'], dataset['Date'], c = dataset['Cluster No'])
    map_ip = pd.concat([dataset['IP'], x['ip']], axis = 1)
    with st.spinner(text="Performing Cluster"):
        res = Freq_Counter(map_ip['IP'].tolist(), map_ip['ip'].tolist())
    file1 = open('suspicious_ip.txt', 'w')
    file1.write(res)
    file1.close()
    st.success("Log File has been sucessfully parsed..")
    file2 = open('suspicious_ip.txt','r')
    st.write("Suspecious IP's : ")
    st.write(file2.read())
    file2.close()
    st.write("Steps to manually block IP ..")
    st.write("$ iptables -A INPUT -s < IP to block > -j DROP")
    st.write("Eg: iptables -A INPUT -s 192.168.73.291 -j DROP")
    st.write("$ service iptables save")


def main():
    st.write('<style>div.Widget.row-widget.stRadio >div{flex-direction:row;}</style>', unsafe_allow_html=True)
    activities = ["Home","Dos Analyzer","About"]
    choice = st.sidebar.selectbox("Select Analysis",activities)
    if choice == 'Home' :
        st.title("WEB BASED SECURITY ANALYZER")
    #st.image(Imag, caption='Sunrise by the mountains',use_column_width=True)
        st.write("Welcome ...!! This project consist of different types of analyzers .The core details of each analyzer are given below ↓ ")
        st.title("DDOS -")
        st.image("images/do.png",width=700,)
        st.write(" Dos Attack is quite common in the web attacks Visualization became one of the solutions in showing the attack on the network. With Visualize the attack, it would be easier in recognizing and concluding the pattern from the complex image visual.")
        st.write("So using K-means Algorithm we can easily find the IP address and block it using the CI/CD tools like Jenkins etc.. It’s an automation program which will scan the web server logs and parse it to csv and then python uses the csv to analyze it and store the attacker IP in a file which will be used to block it")
    elif choice == 'Dos Analyzer':
        st.set_option('deprecation.showfileUploaderEncoding', False)
        log_down = st.file_uploader("Upload Log File to Analyze ")
        c = st.button("Scan" , key=3)
        if c:
            log(log_down)
    elif choice == 'About' :
        st.text("")
        st.text("")
        st.text("")
        st.text("")
        st.subheader("ABOUT WEB BASED SECURITY ANALYZER ")
        st.text("")
        st.text("")
        st.text("")
        st.text("")
        st.text("")
        st.markdown("Built with Streamlit ")
       
    else :
        st.title("NOPE")
if __name__ == '__main__':
    main()