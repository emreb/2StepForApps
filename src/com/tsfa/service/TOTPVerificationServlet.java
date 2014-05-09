package com.tsfa.service;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.labs.repackaged.org.json.JSONException;
import com.google.appengine.labs.repackaged.org.json.JSONObject;
import com.tsfa.modules.TOTP;

@SuppressWarnings("serial")
public class TOTPVerificationServlet extends HttpServlet {

  @Override
  public void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws IOException {

    resp.setContentType("application/json");
    resp.setHeader("Access-Control-Allow-Origin", "*");

    String key = req.getParameter("key");
    String token = req.getParameter("token");
    String range = "3";

    boolean valid = false;
    if (key != null && token != null) {
      try {
        valid = TOTP.verify(key, token, Integer.parseInt(range));
      } catch (Exception e) {

      }
    }

    JSONObject response = new JSONObject();
    try {
      response.put("key", key);
      response.put("token", token);
      response.put("valid", valid);
    } catch (JSONException e) {

    }

    resp.getWriter().print(response.toString());
  }

  @Override
  public void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws IOException {

    doGet(req, resp);
  }
}
