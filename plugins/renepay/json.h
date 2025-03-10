#ifndef LIGHTNING_PLUGINS_RENEPAY_JSON_H
#define LIGHTNING_PLUGINS_RENEPAY_JSON_H

#include "config.h"
#include <plugins/renepay/payment.h>
#include <plugins/renepay/route.h>

struct routekey *tal_routekey_from_json(const tal_t *ctx, const char *buf,
					const jsmntok_t *obj);

struct route *tal_route_from_json(const tal_t *ctx, const char *buf,
				  const jsmntok_t *obj);

struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buffer,
						    const jsmntok_t *toks,
						    struct secret *shared_secrets);

void json_add_payment(struct json_stream *s, const struct payment *payment);

void json_add_route(struct json_stream *s, const struct route *route,
		    const struct payment *payment);

void json_myadd_blinded_path(struct json_stream *s,
			     const char *fieldname,
			     const struct blinded_path *blinded_path);

#endif /* LIGHTNING_PLUGINS_RENEPAY_JSON_H */
