package burp.scan;

import burp.*;
import burp.common.Common;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;


public class SpringBootActuatorScan {
    static List<String> scannedUrls = new ArrayList<>();
    static URL url;
    static String baseurl;
    static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    static PrintWriter stdout;
    static List<List<String>> actuator = new ArrayList<>();
    static{
        actuator.add(Arrays.asList("env","actuator/env"));
        actuator.add(Arrays.asList("java.version"));
        actuator.add((new ArrayList<String>()));
    }
    static List<List<String>> druid = new ArrayList<>();
    static{
        druid.add(Arrays.asList("druid/index.html"));
        druid.add(Arrays.asList("DruidVersion","Druid Stat Index"));
        druid.add((new ArrayList<String>()));
    }
    static List<List<String>> apidoc = new ArrayList<>();
    static{
        apidoc.add(Arrays.asList("v2/api-docs","api-docs","swagger-ui.html"));
        apidoc.add(Arrays.asList("\"swagger\":","swagger-ui.css"));
        apidoc.add((new ArrayList<String>()));
    }
    public synchronized static List<IHttpRequestResponse> ScanMain(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callback, IExtensionHelpers helper,PrintWriter out){
        stdout = out;
        helpers = helper;
        callbacks = callback;
        url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        baseurl = url.getProtocol() + "://" + url.getAuthority();
        List<IHttpRequestResponse> success = new ArrayList<>();
        List headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        stdout.println("开始使用漏扫插件Spring 进行扫描目标: "+ baseurl+url.getPath());
        List<String> scanlists = urlcheck(baseurl);
        if(!actuator.get(2).contains(baseurl)){
            IHttpRequestResponse actuatorscan = actuatorscan(scanlists, headers, baseRequestResponse);
            success.add(actuatorscan);
        }
        if(!druid.get(2).contains(baseurl)){
            IHttpRequestResponse druidscan = druidscan(scanlists, headers, baseRequestResponse);
            success.add(druidscan);
        }
        if(!apidoc.get(2).contains(baseurl)){
            IHttpRequestResponse  apidocscan= apidocscan(scanlists, headers, baseRequestResponse);
            success.add(apidocscan);
        }
        stdout.println(baseurl+url.getPath() + " Spring插件 漏扫结束");
        return success;
    }

    public synchronized static List<String> urlcheck(String baseurl){
        List<String> ScanLists = new ArrayList<>();
        String cross = "";
        String checkurl = baseurl + "/";
        String path = url.getPath().replace("//","/");
        if (path.isEmpty()) path = "/";else path = path;
        String[] paths = path.split("/");
        if (isCheck(checkurl)){
            ScanLists.add(checkurl);
        }
        if(isCheck(checkurl+"..;/")) {
            ScanLists.add(checkurl+"..;/");
        }
        if(url.getPath().endsWith("/")){
            if(isCheck(baseurl+path)){
                ScanLists.add((baseurl+path));
            }
        }
        if (paths.length >= 3){
         for(int i=1;i< paths.length-1;i++){
             checkurl = checkurl + paths[i] + "/";
             cross = cross + "..;/";
             String CrossUrl = checkurl + cross;
             if(isCheck(checkurl)){
                 ScanLists.add(checkurl);
             }
             if(isCheck(CrossUrl)){
                 ScanLists.add(CrossUrl);
             }
         }
        }
        return ScanLists;
    }
    public static Boolean isCheck(String url){
        String urlmd5 = Common.MD5(url);
        if (scannedUrls.contains(urlmd5)){
            stdout.println("已扫描,跳过: "+ url);
            return false;
        }else{
            scannedUrls.add(urlmd5);
            return true;
        }
    }

    public static IHttpRequestResponse actuatorscan(List<String> scanlists,List headers,IHttpRequestResponse baseRequestResponse){
        for(String scanlist:scanlists){
            for(String actuatorpoc:actuator.get(0)){
                String exp = "GET " + scanlist.replace(baseurl,"") + actuatorpoc + " HTTP/1.1";
                stdout.println("actuatorscan exp: "+ exp);
                headers.set(0,exp);
                byte[] body = helpers.buildHttpMessage(headers, null);
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                int bodyOffset = helpers.analyzeResponse(requestResponse.getResponse()).getBodyOffset();
                String resp =new  String(requestResponse.getResponse());
                String respbody = resp.substring(bodyOffset);
                for(String key:actuator.get(1)){
                    if(respbody.contains(key)){
                        List<String> acturl = actuator.get(2);
                        acturl.add(baseurl);
                        actuator.set(2,acturl);
                        return requestResponse;
                    }
                }
            }
        }
        return null;
    }
    public static IHttpRequestResponse druidscan(List<String> scanlists,List headers,IHttpRequestResponse baseRequestResponse){
        for(String scanlist:scanlists){
            for(String druidpoc:druid.get(0)){
                String exp = "GET " + scanlist.replace(baseurl,"") + druidpoc + " HTTP/1.1";
                stdout.println("druidscan exp: "+ exp);
                headers.set(0,exp);
                byte[] body = helpers.buildHttpMessage(headers, null);
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                int bodyOffset = helpers.analyzeResponse(requestResponse.getResponse()).getBodyOffset();
                String resp =new  String(requestResponse.getResponse());
                String respbody = resp.substring(bodyOffset);
                for(String key:druid.get(1)){
                    if(respbody.contains(key)){
                        List<String> acturl = druid.get(2);
                        acturl.add(baseurl);
                        druid.set(2,acturl);
                        return requestResponse;
                    }
                }
            }
        }
        return null;
    }
    public static IHttpRequestResponse apidocscan(List<String> scanlists,List headers,IHttpRequestResponse baseRequestResponse){
        for(String scanlist:scanlists){
            for(String apidocpoc:apidoc.get(0)){
                String exp = "GET " + scanlist.replace(baseurl,"") + apidocpoc + " HTTP/1.1";
                stdout.println("apidocscan exp: "+ exp);
                headers.set(0,exp);
                byte[] body = helpers.buildHttpMessage(headers, null);
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                int bodyOffset = helpers.analyzeResponse(requestResponse.getResponse()).getBodyOffset();
                String resp =new  String(requestResponse.getResponse());
                String respbody = resp.substring(bodyOffset);
                for(String key:apidoc.get(1)){
                    if(respbody.contains(key)){
                        List<String> acturl = apidoc.get(2);
                        acturl.add(baseurl);
                        apidoc.set(2,acturl);
                        return requestResponse;
                    }
                }
            }
        }
        return null;
    }
}
