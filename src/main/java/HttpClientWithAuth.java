/**
 * Created by chenyuzhi on 17-11-16.
 */

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by cyz on 2017/11/23
 * Update date:
 * Time: 18:33
 * Describle :
 * Result of Test:测试通过
 * Command:
 * Email: chenyuzhi459@gmail.com
 */
public class HttpClientWithAuth {

	public static String user ="cyz@SUGO.COM";
	public static String keytab="/softWare/idea/projects/kerberos/keytabs/cyz.keytab";
	public static String krb5Location="/etc/krb5.conf";
	public static String isDebugStr = "false";
	private String principal ;
	private String keyTabLocation ;

	public HttpClientWithAuth(String principal, String keyTabLocation, String krb5Location) {
		this.principal = principal;
		this.keyTabLocation = keyTabLocation;
		System.setProperty("java.security.krb5.conf", krb5Location);
		System.setProperty("sun.security.spnego.debug", isDebugStr);  //
		System.setProperty("sun.security.krb5.debug", isDebugStr);
	}

	//模拟curl命令使用kerberos认证
	private static HttpClient buildSpengoHttpClient() {
		HttpClientBuilder builder = HttpClientBuilder.create();
		Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create().
				register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory(true)).build();   //采用 SPNEGO 认证方案
			builder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
		BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();      //kerberos的ticket提供者
		credentialsProvider.setCredentials(new AuthScope(null, -1, null), new Credentials() {
			@Override
			public Principal getUserPrincipal() {
				return null;
			}
			@Override
			public String getPassword() {
				return null;
			}
		});
		builder.setDefaultCredentialsProvider(credentialsProvider);
		CloseableHttpClient httpClient = builder.build();
		return httpClient;
	}

	//配置kerberos属性
	private  Configuration getKerberosConfig(){
		return new Configuration() {
			@SuppressWarnings("serial")
			@Override
			public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
				return new AppConfigurationEntry[] { new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
						AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap<String, Object>() {
					{
						put("useTicketCache", "false");
						put("useKeyTab", "true");
						put("keyTab", keyTabLocation);
						//Krb5 in GSS API needs to be refreshed so it does not throw the error
						//Specified version of key is not available
						put("refreshKrb5Config", "true");
						put("principal", principal);
						put("storeKey", "true");
						put("doNotPrompt", "true");
						put("isInitiator", "true");
						put("debug", isDebugStr);
					}
				}) };
			}
		};
	}

	//Http Get Method
	public HttpResponse callRestUrl(final String url,final String userId) {
		System.out.println(String.format("Calling KerberosHttpClient %s %s %s",this.principal, this.keyTabLocation, url));
		Set<Principal> princ = new HashSet<Principal>(1);
		princ.add(new KerberosPrincipal(userId));
		Subject sub = new Subject(false, princ, new HashSet<Object>(), new HashSet<Object>());
		try {
			//认证模块：Krb5Login
			LoginContext lc = new LoginContext("Krb5Login", sub, null, getKerberosConfig());
			lc.login();
			Subject serviceSubject = lc.getSubject();
			return Subject.doAs(serviceSubject, new PrivilegedAction<HttpResponse>() {
				HttpResponse httpResponse = null;
				@Override
				public HttpResponse run() {
					try {
						HttpUriRequest request = new HttpGet(url);

						HttpClient spnegoHttpClient = buildSpengoHttpClient();
						httpResponse = spnegoHttpClient.execute(request);
						return httpResponse;
					} catch (IOException ioe) {
						ioe.printStackTrace();
					}
					return httpResponse;
				}
			});
		} catch (Exception le) {
			le.printStackTrace();
		}
		return null;
	}

	//Http Post Method
	public HttpResponse postRestUrl(final String url,final String userId,final String params) {
		System.out.println(String.format("Calling KerberosHttpClient %s %s %s",this.principal, this.keyTabLocation, url));
		Set<Principal> princ = new HashSet<Principal>(1);
		princ.add(new KerberosPrincipal(userId));
		Subject sub = new Subject(false, princ, new HashSet<Object>(), new HashSet<Object>());
		try {
			//认证模块：Krb5Login
			LoginContext lc = new LoginContext("Krb5Login", sub, null, getKerberosConfig());
			lc.login();
			Subject serviceSubject = lc.getSubject();
			return Subject.doAs(serviceSubject, new PrivilegedAction<HttpResponse>() {
				HttpResponse httpResponse = null;
				@Override
				public HttpResponse run() {
					try {
						StringEntity entity = new StringEntity(params,"UTF-8");
						entity.setContentEncoding("UTF-8");
						entity.setContentType("application/json");
						HttpPost httpPost = new HttpPost(url);
						httpPost.setEntity(entity);

						HttpClient spnegoHttpClient = buildSpengoHttpClient();
						httpResponse = spnegoHttpClient.execute(httpPost);
						return httpResponse;
					} catch (IOException ioe) {
						ioe.printStackTrace();
					}
					return httpResponse;
				}
			});
		} catch (Exception le) {
			le.printStackTrace();
		}
		return null;
	}

	public static void main(String[] args) throws UnsupportedOperationException, IOException {

		HttpClientWithAuth restTest = new HttpClientWithAuth(user,keytab,krb5Location);

		String supervisorUrl = "http://dev225.sugo.net:8090/druid/indexer/v1/supervisor";

		String params = "{\n" +
				"  \"queryType\":\"lucene_timeBoundary\",\n" +
				"  \"dataSource\":\"druid-test002\",\n" +
				"  \"context\":null,\n" +
				"  \"intervals\":\"1000/3000\",\n" +
				"  \"bound\":null\n" +
				"}";
		String brokerUrl = "http://dev225.sugo.net:8082/druid/v2?pretty";

		HttpResponse response = restTest.postRestUrl(brokerUrl,user,params);  //查询数据源的maxTime,minTime
		printResponse(response);

		response = restTest.callRestUrl(supervisorUrl,user);    //获取正在运行的supervisor
		printResponse(response);
	}

	public static void printResponse(HttpResponse response) throws IOException {
		System.out.println("Status code " + response.getStatusLine().getStatusCode());
//		System.out.println("message is :"+Arrays.deepToString(response.getAllHeaders()));
		System.out.println("返回值：\n"+new String(IOUtils.toByteArray(response.getEntity().getContent()), "UTF-8"));
	}
}