package security.org.jwt.util;

public class AjaxReponse {
	private int status;
	private String message;
	private Object data;

	public AjaxReponse() {
		super();
	}

	public AjaxReponse(int status, String message) {
		this.status = status;
		this.message = message;

	}

	public AjaxReponse(int status, String message, Object data) {
		this.status = status;
		this.message = message;
		this.data = data;
	}

	public int getStatus() {
		return status;
	}

	public String getMessage() {
		return message;
	}

	public Object getData() {
		return data;
	}

	public void setData(Object data) {
		this.data = data;
	}

	public void setStatus(int status) {
		this.status = status;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}
