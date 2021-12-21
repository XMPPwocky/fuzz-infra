#include <rlottie.h>

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
      // cachePolicy false!
        auto player = rlottie::Animation::loadFromData(data, false);
        if (!player) return help();

        auto buffer = std::unique_ptr<uint32_t[]>(new uint32_t[w * h]);
        size_t frameCount = player->totalFrame();

        for (size_t i = 0; i < frameCount ; i++) {
            rlottie::Surface surface(buffer.get(), w, h, w * 4);
            player->renderSync(i, surface);
        }
        return result();
    }

    int setup(int argc, char **argv)
    {
        return 0;
    }

private:
    std::string basename(const std::string &str)
    {
        return str.substr(str.find_last_of("/\\") + 1);
    }

    int result() {
        return 0;
    }

    int help() {
        std::cout<<"Usage: \n   lottie2gif [lottieFileName] [bgColor]\n\nExamples: \n    $ lottie2gif input.json\n    $ lottie2gif input.json ff00ff\n\n";
        return 1;
    }

private:
    int bgColor = 0xffffffff;
};


int
main(int argc, char **argv)
{
    App app;

    if (app.setup(argc, argv)) return 1;
    
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

    std::string data;
    data.reserve(131072);
    while (__AFL_LOOP(10000)) {
      data.clear();

      int len = __AFL_FUZZ_TESTCASE_LEN;

      data.append(buf, len);

      app.render(data, 16, 16);
    }


    return 0;
}
