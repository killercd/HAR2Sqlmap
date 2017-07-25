#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#Prof: HAR2Sqlmap
#Description: Convert HAR file to Sqlmap command attack
#Author: killercd

import sys
import argparse
import json
from pprint import pprint

def extractHeader(request):
    if not request:
        return request["headers"]
    return []
        
def extractCookies(request):
    if not request:
        return request["cookies"]
    return []

def toSqlMapHeader(headerList):
    if not headerList:
        headerStr = "--headers "
        pprint(headerList) 
        for header in headerList:
            headerStr = headerStr+header['name']+": "+header['value']+"\n"
        return headerStr
    return []
        
        
def main():


    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=argparse.FileType('r'))
    args = parser.parse_args() 
    
    data = json.load(args.file)
    for entries in data["log"]["entries"]:
            if "request" in entries:
                headerList = extractHeader(entries["request"])
                cookies = extractCookies(entries["request"])
                #toSqlMapHeader(headerList)
                #pprint(toSqlMapHeader(headerList))
                pprint(headerList)                
            
        
        
    
    
        
    

if __name__ == "__main__":
    exit(main())
