package security.org.jwt.util;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.introspect.AnnotatedMethod;

public class JSONUtil {
	private static final Logger log = Logger.getLogger(JSONUtil.class);

	public static final ObjectMapper mapper = new ObjectMapper();

	public static String getJSONString(Object obj) {
		try {
			return mapper.writeValueAsString(obj);
		} catch (JsonProcessingException e) {
			log.error("getJSONString error," + e);
			e.printStackTrace();
		}

		return null;
	}
	public static String getCapitalizedJSONString(Object obj) {
		ObjectMapper objMapper = new ObjectMapper();
		objMapper.setPropertyNamingStrategy(new PropertyNamingStrategy() {
		private static final long serialVersionUID = 1L;
		// 反序列化时调用
		@Override
		public String nameForSetterMethod(MapperConfig<?> config,
				AnnotatedMethod method, String defaultName) {
			return method.getName().substring(3);
		}
		// 序列化时调用
		@Override
		public String nameForGetterMethod(MapperConfig<?> config,
				AnnotatedMethod method, String defaultName) {
			return method.getName().substring(3);
		}
	});
//	        mapper.enable(SerializationFeature.INDENT_OUTPUT);
//	        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        StringWriter sw = new StringWriter();
        try {
        	objMapper.writeValue(sw, obj);
		} catch (JsonGenerationException e) {
			log.error("getJSONString error," + e);
			e.printStackTrace();
		} catch (JsonMappingException e) {
			log.error("getJSONString error," + e);
			e.printStackTrace();
		} catch (IOException e) {
			log.error("getJSONString error," + e);
			e.printStackTrace();
		}
        return sw.toString();
	}

	public static <T> T toCapitalizedObject(String json, Class<T> c) {
		ObjectMapper objMapper = new ObjectMapper();
		objMapper.setPropertyNamingStrategy(new PropertyNamingStrategy() {
		private static final long serialVersionUID = 1L;
		// 反序列化时调用
		@Override
		public String nameForSetterMethod(MapperConfig<?> config,
				AnnotatedMethod method, String defaultName) {
			return method.getName().substring(3);
		}
		// 序列化时调用
		@Override
		public String nameForGetterMethod(MapperConfig<?> config,
				AnnotatedMethod method, String defaultName) {
			return method.getName().substring(3);
		}
	});
        try {
        	return	objMapper.readValue(json, c);
		} catch (JsonGenerationException e) {
			log.error("getJSONString error," + e);
			e.printStackTrace();
		} catch (JsonMappingException e) {
			log.error("getJSONString error," + e);
			e.printStackTrace();
		} catch (IOException e) {
			log.error("getJSONString error," + e);
			e.printStackTrace();
		}
        return null;
	}
	
	public static <T> T toObject(String json, Class<T> c) {
		try {
			return mapper.readValue(json, c);
		} catch (JsonProcessingException e) {
			log.error("json to object error,", e);

		} catch (IOException e) {
			log.error("read io error,", e);
		}
		return null;
	}

	public static <T> T toObject(String json, Class<T> c, String noLog) {
		try {
			return mapper.readValue(json, c);
		} catch (JsonProcessingException e) {
		} catch (IOException e) {
		}
		return null;
	}

	public static <T> List<T> toObjectList(String json, Class<T> c) {
		try {
			return mapper.readValue(json, mapper.getTypeFactory().constructCollectionType(List.class, c));
		} catch (JsonProcessingException e) {
			log.error("json to object error," + e);
			e.printStackTrace();
		} catch (IOException e) {
			log.error("read io error," + e);
			e.printStackTrace();
		}
		return null;
	}

	public static <T> Map<T, T> toObjectMap(String json, Class<T> keyClass, Class<T> valueClass) {
		try {
			return mapper.readValue(json,
					mapper.getTypeFactory().constructMapType(HashMap.class, keyClass, valueClass));
		} catch (JsonProcessingException e) {
			log.error("json to object error," + e);
			e.printStackTrace();
		} catch (IOException e) {
			log.error("read io error," + e);
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String a[]) {
		// String json = "{\"status\":\"processing\",\"data\":\"deploy
		// application finishd successfully\"}";
		// String json2 =
		// "{\"name\":\"name1\",\"note\":\"note1\",\"version\":\"v1\",\"jsonStr\":\"{\"status\":\"processing\",\"data\":\"deploy
		// application finishd
		// successfully\"}\",\"userId\":\"appuser\",\"tenantId\":\"1\"}";
		//
		// RestResult rr = new RestResult();
		// rr.setData("test data2");
		//
		// rr.setStatus("statusOK");
		//
		// // System.out.println(toObject(json, RestResult.class));
		// CreatApp app = new CreatApp();
		// app.setJsonStr(getJSONString(rr));
		// app.setName("name1");
		// app.setNote("note1");
		// app.setTenantId("1");
		// app.setUserId("appuser");
		// app.setVersion("v1");
		//
		// String json3 = getJSONString(app);
		// System.out.println(json3);
		//
		// System.out.println(toObject(json3, CreatApp.class));
	}

	// public static void main(String a[])
	// {
	// String json="{\"status\":\"processing\",\"data\":\"deploy application
	// finishd successfully\"}";
	// String
	// json2="{\"name\":\"name1\",\"note\":\"note1\",\"version\":\"v1\",\"jsonStr\":\"{\"status\":\"processing\",\"data\":\"deploy
	// application finishd
	// successfully\"}\",\"userId\":\"appuser\",\"tenantId\":\"1\"}";
	//
	// RestResult rr=new RestResult();
	//// rr.setData("test data2");
	////
	//// rr.setStatus("statusOK");
	////
	////// System.out.println(toObject(json, RestResult.class));
	//// CreatApp app=new CreatApp();
	//// app.setAppDescription(getJSONString(rr));
	//// app.setName("name1");
	//// app.setNote("note1");
	//// app.setTenantId("1");
	//// app.setUserId("appuser");
	//// app.setVersion("v1");
	////
	//// String json3=getJSONString(app);
	//// System.out.println(json3);
	//
	// String json3 =getJSONString(new Tenant());
	//
	// Tenant t= toObject(json3,Tenant.class);
	//
	// System.out.println();
	// }
}
