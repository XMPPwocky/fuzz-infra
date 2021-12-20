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

class App {
public:
    int render(uint32_t w, uint32_t h)
    {
      // cachePolicy false!
        auto player = rlottie::Animation::loadFromFile(fileName, false);
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
        char *path{nullptr};

        if (argc > 1) path = argv[1];
        if (argc > 2) bgColor = strtol(argv[2], NULL, 16);

        if (!path) return help();

        std::array<char, 5000> memory;

#ifdef _WIN32
        path = _fullpath(memory.data(), path, memory.size());
#else
        path = realpath(path, memory.data());
#endif
        if (!path) return help();

        fileName = std::string(path);

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
    std::string fileName;
};

int
main(int argc, char **argv)
{
    App app;

    if (app.setup(argc, argv)) return 1;

    while (__AFL_LOOP(1000)) {
      app.render(32, 32);
    }


    return 0;
}
