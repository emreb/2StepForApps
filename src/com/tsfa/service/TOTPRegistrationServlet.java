package com.tsfa.service;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.labs.repackaged.org.json.JSONException;
import com.google.appengine.labs.repackaged.org.json.JSONObject;
import com.tsfa.modules.TOTP;

@SuppressWarnings("serial")
public class TOTPRegistrationServlet extends HttpServlet {

  @Override
  public void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws IOException {

    resp.setContentType("application/json");
    resp.setHeader("Access-Control-Allow-Origin", "*");
    String app = req.getParameter("app");
    if (app == null) {
      app = "";
    }

    String user = req.getParameter("user");
    if (user == null) {
      user = "";
    }

    String key = TOTP.randomId(50);
    String url = TOTP.getQRCodeURL(app, user, key);

    JSONObject j = new JSONObject();
    try {
      j.put("app", app);
      j.put("user", user);
      j.put("url", url);
      j.put("key", key);
    } catch (JSONException e) {

    }

    resp.getWriter().print(j.toString());
  }

  @Override
  public void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws IOException {

    doGet(req, resp);
  }
}
