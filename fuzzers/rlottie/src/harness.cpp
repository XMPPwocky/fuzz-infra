#include <rlottie.h>

#include <unistd.h>
#include<iostream>
#include<string>
#include<vector>
#include<array>

#ifndef _WIN32
#include<libgen.h>
#else
#include <windows.h>
#include <stdlib.h>
#endif

__AFL_FUZZ_INIT();

class App {
  public:
    int render(std::string data, uint32_t w, uint32_t h)
    {
      printf("%s\n", data.c_str());
      // cachePolicy false
      auto player = rlottie::Animation::loadFromData(data, data); //, "", "", false);
      if (!player) return 0;

      auto buffer = std::unique_ptr<uint32_t[]>(new uint32_t[w * h]);
      size_t frameCount = player->totalFrame();

      for (size_t i = 0; i < frameCount ; i++) {
        rlottie::Surface surface(buffer.get(), w, h, w * 4);
        player->renderSync(i, surface);
      }
      return frameCount;
    }

  private:
    int bgColor = 0xffffffff;

    int dumbCounter = 0;
};


  int
main(int argc, char **argv)
{
  App app;

  app.render("{}", 32, 32);

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

   while (__AFL_LOOP(100000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;

    app.render((char*)buf, 32, 32);
  }

  return 0;
}
