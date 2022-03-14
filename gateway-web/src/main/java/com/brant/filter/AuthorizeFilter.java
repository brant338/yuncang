package com.changgou.filter;

import com.changgou.util.JwtUtil;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthorizeFilter implements GlobalFilter, Ordered {
    private static final String AUTHORIZE_TOKEN = "Authorization";
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //获取请求对象和响应对象
        ServerHttpRequest request = exchange.getRequest();

        ServerHttpResponse response = exchange.getResponse();
        //判断路径权限
        if(request.getURI().getPath().startsWith("user/api/search")){
            //4.从请求头中获取令牌  如果获取不到
            String token = request.getHeaders().getFirst(AUTHORIZE_TOKEN);
            if(StringUtils.isEmpty(token)){
                //5.再从请求参数中获取令牌  如果获取不到
                token = request.getQueryParams().getFirst(AUTHORIZE_TOKEN);
            }
            if(StringUtils.isEmpty(token)){
                //6.再从cookie中获取令牌 如果获取不到
                HttpCookie cookie = request.getCookies().getFirst(AUTHORIZE_TOKEN);
                if(cookie!=null){
                    token= cookie.getValue();
                }
            }
            if(StringUtils.isEmpty(token)){
                //令牌为空 返回
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
                //或者重定向到登录页面
            }

            //解析令牌,解析失败,返回
            try {
                JwtUtil.parseJWT(token);
            } catch (Exception e) {
                e.printStackTrace();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
                //或者重定向到登录页面
            }

            //放行
            return chain.filter(exchange);

        }else{
            //放行
            chain.filter(exchange);
        }
        //放行
        return chain.filter(exchange);
    }


    //过滤器的order的值越低,越优先执行
    @Override
    public int getOrder() {
        return 0;
    }
}
