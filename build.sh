#!/bin/bash
set -euo pipefail

vuedev='<script src="https://cdn\.jsdelivr\.net/npm/vue@2/dist/vue.js"></script>'
vueprod='<script src="https://cdn\.jsdelivr\.net/npm/vue@2\.6\.12/dist/vue\.min\.js" integrity="sha384-cwVe6U8Tq7F/3JIj6xeDzOwuqeChcmRcdYqDGfoYmdAurw7L3f4dFHhEJKfxv96A" crossorigin="anonymous"></script>'

echo " + Copying CSS files to public/"
cp -R css public/
echo " + Copying JavasCript files to public/"
cp -R js public/
echo " + Copying index.html to public/"
cp index.html public/
echo " + Replacing development Vue script with production version"
if [[ "$OSTYPE" == "darwin"* ]]; then
  sed -i '' -e "s|${vuedev}|${vueprod}|g" public/index.html
else
  sed -i -e "s|${vuedev}|${vueprod}|g" public/index.html
fi

echo " + Done!"