#include <iostream>
#ifdef PRIVACY_PASS
#include "crypto/ep_group/ep.h"
#include "crypto/privacy_pass/server.h"
#include "networking/PPServer.h"
#include "networking/PPClient.h"
#else
#include "networking/GVRFServer.h"
#include "networking/GVRFClient.h"
#endif
#include "config.h"

// To Do: Networking code needs better readability
int main(int argc, char **argv)
{
  Config config = create_config(argc, argv);

#ifdef PRIVACY_PASS
  EpGroup::config();
  std::cout << "Benchmarking Privacy Pass..." << std::endl;
  if (config.is_server)
  {
    PrivacyPass::start_server(config);
  }
  else
  {
    PrivacyPass::WebClient wc = PrivacyPass::WebClient(config);
    wc.get_and_redeem_tokens(config.amount, config.runs);
  }
#else
  BilinearGroup::config();
  std::cout << "Benchmarking GVRF..." << std::endl;

  if (config.is_server)
  {
    GVRF::start_server(config);
  }
  else
  {
    int l = 2;
    GVRF::WebClient wc = GVRF::WebClient(config, &l);
    wc.get_and_redeem_tokens(config.amount, config.runs);
  }
#endif
  return 0;
}
