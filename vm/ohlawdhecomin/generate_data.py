from PIL import Image

img = Image.open('ohlawdhecomin.gif')

data = []

for frame in range(0, img.n_frames):
    img.seek(frame)
    rgba = img.convert('RGBA')

    data.append([
        [
            rgba.getpixel((x, y))
            for x in range(img.width)
        ]
        for y in range(img.height)
    ])

with open('ohlawdhecomin.h', 'w') as f:
    print(f'#define OHLAWDHECOMIN_F {img.n_frames}', file=f)
    print(f'#define OHLAWDHECOMIN_W {img.width}', file=f)
    print(f'#define OHLAWDHECOMIN_H {img.height}', file=f)
    print(file=f)
    print('static u32 ohlawdhecomin_data[OHLAWDHECOMIN_F][OHLAWDHECOMIN_H]'
          '[OHLAWDHECOMIN_W] = {', file=f)
    for frame in data:
        print('\t{', file=f)
        for h in frame:
            print('\t\t{', file=f, end='')
            for w in h:
                r, g, b, a = w

                if a:
                    d = (r << 16) | (g << 8) | b
                else:
                    d = 0

                print(f'{hex(d)}, ', file=f, end='')

            print('},', file=f)
        print('\t},', file=f)
    print('};', file=f)
