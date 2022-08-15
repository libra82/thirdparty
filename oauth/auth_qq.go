package oauth

import (
	"errors"
	"github.com/libra82/thirdparty/result"
	"github.com/libra82/thirdparty/utils"
)

//QQ授权登录
type AuthQq struct {
	BaseRequest
}

func NewAuthQq(conf *AuthConfig) *AuthQq {
	authRequest := &AuthQq{}
	authRequest.Set(utils.RegisterSourceQQ, conf)

	authRequest.authorizeUrl = "https://graph.qq.com/oauth2.0/authorize"
	authRequest.TokenUrl = "https://graph.qq.com/oauth2.0/token"
	authRequest.openUnionIdUrl = "https://graph.qq.com/oauth2.0/me"
	authRequest.userInfoUrl = "https://graph.qq.com/user/get_user_info"

	return authRequest
}

//获取登录地址
func (a *AuthQq) GetRedirectUrl(state string) (*result.CodeResult, error) {
	url := utils.NewUrlBuilder(a.authorizeUrl).
		AddParam("response_type", "code").
		AddParam("client_id", a.config.ClientId).
		AddParam("redirect_uri", a.config.RedirectUrl).
		AddParam("state", a.GetState(state)).
		Build()

	_, err := utils.Post(url)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

//获取token
func (a *AuthQq) GetToken(code string) (*result.TokenResult, error) {
	url := utils.NewUrlBuilder(a.TokenUrl).
		AddParam("grant_type", "authorization_code").
		AddParam("code", code).
		AddParam("client_id", a.config.ClientId).
		AddParam("client_secret", a.config.ClientSecret).
		AddParam("redirect_uri", a.config.RedirectUrl).
		Build()

	body, err := utils.Post(url)
	if err != nil {
		return nil, err
	}
	m := utils.JsonToMSS(body)
	if _, ok := m["error"]; ok {
		return nil, errors.New(m["error_description"])
	}
	token := &result.TokenResult{
		AccessToken:  m["access_token"],
		RefreshToken: m["refresh_token"],
		ExpireIn:     m["expires_in"],
		Scope:        m["scope"],
		TokenType:    m["token_type"],
	}
	return token, nil
}

//获取第三方用户信息
func (a *AuthQq) GetUserInfo(openId string, accessToken string) (*result.UserResult, error) {
	url := utils.NewUrlBuilder(a.userInfoUrl).
		AddParam("openid", openId).
		AddParam("access_token", accessToken).
		AddParam("oauth_consumer_key", a.config.ClientId).
		Build()

	body, err := utils.Get(url)
	if err != nil {
		return nil, err
	}
	m := utils.JsonToMSS(body)
	if _, ok := m["error"]; ok {
		return nil, errors.New(m["error_description"])
	}
	logo := m["figureurl_qq_2"] //大小为100×100像素的QQ头像URL。需要注意，不是所有的用户都拥有QQ的100x100的头像，但40x40像素则是一定会有。
	if len(logo) == 0 {
		logo = m["figureurl_qq_1"] //大小为40×40像素的QQ头像URL。
	}
	user := &result.UserResult{
		NickName:  m["nickname"], //用户在QQ空间的昵称。
		AvatarUrl: logo,
		Location:  m["province"] + m["city"],
		City:      m["city"],     //普通用户个人资料填写的城市
		Province:  m["province"], //普通用户个人资料填写的省份
		Source:    a.registerSource,
		Gender:    utils.GetRealGender(m["gender"]).Desc,
	}
	return user, nil
}
