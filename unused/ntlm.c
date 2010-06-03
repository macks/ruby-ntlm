/* vim: set et sw=2:
 *
 * NTLM for Ruby
 *   by MATSUYAMA Kengo
 *
 */

#include <ntlm.h>
#include <ruby.h>

static VALUE mNTLM;

static VALUE
ntlm_negotiate(VALUE obj)
{
  tSmbNtlmAuthRequest request;
  buildSmbNtlmAuthRequest(&request, "Workstation", "Domain");
  return rb_str_new((const char *)&request, SmbLength(&request));
}

static VALUE
ntlm_authenticate(VALUE obj, VALUE challenge, VALUE user_at_domain, VALUE password)
{
  tSmbNtlmAuthResponse response;

  Check_Type(challenge, T_STRING);
  Check_Type(user_at_domain, T_STRING);
  Check_Type(password, T_STRING);

  buildSmbNtlmAuthResponse((tSmbNtlmAuthChallenge *)RSTRING_PTR(challenge), &response, RSTRING_PTR(user_at_domain), RSTRING_PTR(password));

  return rb_str_new((const char *)&response, SmbLength(&response));
}

void Init_ntlm()
{
  mNTLM = rb_define_module("NTLM");
  rb_define_module_function(mNTLM, "negotiate", ntlm_negotiate, 0);
  rb_define_module_function(mNTLM, "authenticate", ntlm_authenticate, 3);
}
