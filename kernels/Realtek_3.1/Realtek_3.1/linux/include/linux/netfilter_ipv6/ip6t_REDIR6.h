#ifndef _XT_REDIR6_H
#define _XT_REDIR6_H

struct xt_redir6_target_info_v1 {
        union nf_inet_addr laddr;
        __be16 lport;
};

#endif /* _XT_REDIR6_H */

