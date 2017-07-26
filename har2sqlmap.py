#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#Prog: HAR2Sqlmap
#Description: Convert HAR file to Sqlmap command attack
#Author: killercd


import argparse
import json



NEWLINE = "\\n"
ENDCOOKIE = ";"
ENDPOSTDATA = "&"
EXCLUDE_HEADER_LIST = ["cookie"]
EXCLUDE_COOKIE_LIST = []
STRING_SEPARATOR = "\""
PROGSTART = "python sqlmap.py -u "
APPENDSTR = ""
def getUrl(request):
    if request:
        return request["url"]
    return ""
def extractHeader(request):
    if request:
        return request["headers"]
    return []
        
def extractCookies(request):
    if request:
        return request["cookies"]
    return []

def extractPostData(dataList):
    
    if dataList:
        return dataList["queryString"]
    return []
def toSqlMapHeader(headerList):
    if headerList:
        headerStr = "--headers \""
        
        for header in headerList:
            if not header["name"] in EXCLUDE_HEADER_LIST:
                headerStr = headerStr+header['name']+": "+header['value']+NEWLINE
        headerStr = headerStr+"\""
        return headerStr
    return ""
def toSqlMapCookies(cookiesList):
    if cookiesList:
        cookieStr = "--cookie \""
        for cookie in cookiesList:
            if not cookie["name"] in EXCLUDE_COOKIE_LIST:
                cookieStr = cookieStr+cookie['name'] +"="+cookie['value']+ENDCOOKIE
        cookieStr = cookieStr+"\""
        return cookieStr
    return ""

def toSqlMapData(dataList):
    if dataList:
        dataStr = "--data \""
        for data in dataList:
            dataStr = dataStr+data['name']+"="+data['name']+ENDPOSTDATA
        return dataStr
    return ""
def isPOST(request):
    
    if request and "method" in request and request["method"]=="POST":
        return True
    else:
        return False
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=argparse.FileType('r'))
    args = parser.parse_args() 
    
    data = json.load(args.file)
    for entries in data["log"]["entries"]:
            if "request" in entries:
                requestJSON = entries["request"]
                headerList = extractHeader(requestJSON)
                cookies = extractCookies(requestJSON)
                programFullCommand = PROGSTART
                cmdData=""
                if isPOST(requestJSON):
                    postDataList = extractPostData(requestJSON)
                    cmdData = "--method POST "+toSqlMapData(postDataList)
                    
                programFullCommand = programFullCommand+STRING_SEPARATOR+getUrl(requestJSON)+STRING_SEPARATOR+" "+cmdData+" "+toSqlMapCookies(cookies)+" "+toSqlMapHeader(headerList)+APPENDSTR
                print programFullCommand
                #toSqlMapHeader(headerList)
                #print(toSqlMapHeader(headerList))
                #print(toSqlMapCookies(cookies))
                #pprint(cookies)                
            
        
        
    
    
        
    

if __name__ == "__main__":
    exit(main())
