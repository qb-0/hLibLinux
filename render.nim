import strutils, math, colors, osproc
import nimgl/[glfw, opengl]
import opengl/glut
import input

type
  Overlay* = object
    width*, height*, midX*, midY*: int32
    x*, y*: int32
    videoMode*: ptr GLFWVidMode
    window*: GLFWWindow
    exitKey*: culong

  Vec2* = object
    x*, y*: float32

  Vec3* = object
    x*, y*, z*: float32

  Rgb* = tuple
    r, g, b: float32

  WinInfo = tuple
    x, y, width, height: int32

#[
  misc
]#

proc newRgb*(r, g, b: float32): Rgb =
  result.r = r
  result.g = g
  result.b = b

proc color*(color: string): Rgb =
  try:
    var c = parseColor(color).extractRGB()
    result.r = c.r.float32
    result.g = c.g.float32
    result.b = c.b.float32
  except:
    result = newRgb(0, 0, 0)

#[
  vector
]#

proc Vector*(x: float32, y: float32): Vec2 =
  Vec2(x: x, y: y)
proc Vector*(x: float32, y: float32, z: float32): Vec3 =
  Vec3(x: x, y: y, z: z)

proc `+`*(self: Vec2, v: Vec2): Vec2 =
  Vec2(x: self.x + v.x, y: self.y + v.y)
proc `+`*(self: Vec3, v: Vec3): Vec3 =
  Vec3(x: self.x + v.x, y: self.y + v.y, z: self.z + v.z)
proc `+`*(self: Vec2, v: float32): Vec2 =
  Vec2(x: self.x + v, y: self.y + v)
proc `+`*(self: Vec3, v: float32): Vec3 =
  Vec3(x: self.x + v, y: self.y + v, z: self.z + v)

proc `+=`*(self: var Vec2, v: float32) =
  self.x = self.x + v
  self.y = self.y + v
proc `+=`*(self: var Vec3, v: float32) =
  self.x = self.x + v
  self.y = self.y + v
  self.z = self.z + v
proc `+=`*(self: var Vec2, v: Vec2) =
  self.x = self.x + v.x
  self.y = self.y + v.y
proc `+=`*(self: var Vec3, v: Vec3) =
  self.x = self.x + v.x
  self.y = self.y + v.y
  self.z = self.z + v.z

proc `-`*(self: Vec2, v: Vec2): Vec2 =
  Vec2(x: self.x - v.x, y: self.y - v.y)
proc `-`*(self: Vec3, v: Vec3): Vec3 =
  Vec3(x: self.x - v.x, y: self.y - v.y, z: self.z - v.z)
proc `-`*(self: Vec2, v: float32): Vec2 =
  Vec2(x: self.x - v, y: self.y - v)
proc `-`*(self: Vec3, v: float32): Vec3 =
  Vec3(x: self.x - v, y: self.y - v, z: self.z - v)

proc `-=`*(self: var Vec2, v: float32) =
  self.x = self.x - v
  self.y = self.y - v
proc `-=`*(self: var Vec3, v: float32) =
  self.x = self.x - v
  self.y = self.y - v
  self.z = self.z - v
proc `-=`*(self: var Vec2, v: Vec2) =
  self.x = self.x - v.x
  self.y = self.y - v.y
proc `-=`*(self: var Vec3, v: Vec3) =
  self.x = self.x - v.x
  self.y = self.y - v.y
  self.z = self.z - v.z

proc `*`*(self: Vec2, v: Vec2): Vec2 =
  Vec2(x: self.x * v.x, y: self.y * v.y)
proc `*`*(self: Vec3, v: Vec3): Vec3 =
  Vec3(x: self.x * v.x, y: self.y * v.y, z: self.z * v.z)
proc `*`*(self: Vec2, v: float32): Vec2 =
  Vec2(x: self.x * v, y: self.y * v)
proc `*`*(self: Vec3, v: float32): Vec3 =
  Vec3(x: self.x * v, y: self.y * v, z: self.z * v)

proc `*=`*(self: var Vec2, v: float32) =
  self.x = self.x * v
  self.y = self.y * v
proc `*=`*(self: var Vec3, v: float32) =
  self.x = self.x * v
  self.y = self.y * v
  self.z = self.z * v
proc `*=`*(self: var Vec2, v: Vec2) =
  self.x = self.x * v.x
  self.y = self.y * v.y
proc `*=`*(self: var Vec3, v: Vec3) =
  self.x = self.x * v.x
  self.y = self.y * v.y
  self.z = self.z * v.z

proc `/`*(self: Vec2, v: Vec2): Vec2 =
  Vec2(x: self.x / v.x, y: self.y / v.y)
proc `/`*(self: Vec3, v: Vec3): Vec3 =
  Vec3(x: self.x / v.x, y: self.y / v.y, z: self.z / v.z)
proc `/`*(self: Vec2, v: float32): Vec2 =
  Vec2(x: self.x / v, y: self.y / v)
proc `/`*(self: Vec3, v: float32): Vec3 =
  Vec3(x: self.x / v, y: self.y / v, z: self.z / v)

proc `/=`*(self: var Vec2, v: float32) =
  self.x = self.x / v
  self.y = self.y / v
proc `/=`*(self: var Vec3, v: float32) =
  self.x = self.x / v
  self.y = self.y / v
  self.z = self.z / v
proc `/=`*(self: var Vec2, v: Vec2) =
  self.x = self.x / v.x
  self.y = self.y / v.y
proc `/=`*(self: var Vec3, v: Vec3) =
  self.x = self.x / v.x
  self.y = self.y / v.y
  self.z = self.z / v.z

proc magSq*(self: Vec2): float32 =
  (self.x * self.x) + (self.y * self.y)
proc magSq*(self: Vec3): float32 =
  (self.x * self.x) + (self.y * self.y) + (self.z * self.z)

proc mag*(self: Vec2): float32 =
  sqrt(self.magSq())
proc mag*(self: Vec3): float32 =
  sqrt(self.magSq())

proc dist*(self: Vec2, v: Vec2): float32 =
  mag(self - v)
proc dist*(self: Vec3, v: Vec3): float32 =
  mag(self - v)

proc normalize*(self: var Vec2) =
  self /= self.mag()
proc normalize*(self: var Vec3) =
  self /= self.mag()

proc perpendicular*(self: Vec2): Vec2 =
  result.x = -self.y
  result.y = self.x

#[
  overlay
]#

proc getWindowInfo(name: string): WinInfo =
  let 
    p = startProcess("xwininfo", "", ["-name", name], options={poUsePath, poStdErrToStdOut})
    (lines, exitCode) = p.readLines()

  template parseI: int32 = parseInt(i.split()[^1]).int32

  if exitCode != 1:
    for i in lines:
      if "te upper-left X:" in i:
        result.x = parseI
      elif "te upper-left Y:" in i:
        result.y = parseI
      elif "Width:" in i:
        result.width = parseI
      elif "Height:" in i:
        result.height = parseI
  else:
    raise newException(IOError, "XWinInfo failed")

proc initOverlay*(name: string = "Overlay", target: string = "Fullscreen", exitKey: culong = XK_End): Overlay =
  var wInfo: WinInfo
  assert glfwInit()

  glfwWindowHint(GLFWFloating, GLFWTrue)
  glfwWindowHint(GLFWDecorated, GLFWFalse)
  glfwWindowHint(GLFWResizable, GLFWFalse)
  glfwWindowHint(GLFWTransparentFramebuffer, GLFWTrue)
  glfwWindowHint(GLFWSamples, 10)
  glfwWindowHint(GLFWMouseButtonPassthrough, GLFWTrue)

  result.videoMode = getVideoMode(glfwGetPrimaryMonitor())
  if target == "Fullscreen":
    result.width = result.videoMode.width - 1
    result.height = result.videoMode.height - 1
    result.midX = result.videoMode.width div 2
    result.midY = result.videoMode.height div 2
    result.x = 0
    result.y = 0
  else:
    wInfo = getWindowInfo(target)
    result.width = wInfo.width
    result.height = wInfo.height
    result.x = wInfo.x
    result.y = wInfo.y
    result.midX = result.width div 2
    result.midY = result.height div 2

  result.exitKey = exitKey
  result.window = glfwCreateWindow(result.width.int32, result.height.int32, name, icon=false)
  result.window.makeContextCurrent()
  glfwSwapInterval(1)
  
  assert glInit()
  glutInit()
  glPushAttrib(GL_ALL_ATTRIB_BITS)
  glMatrixMode(GL_PROJECTION)
  glLoadIdentity()
  glOrtho(0, result.width.float64, 0, result.height.float64, -1, 1)
  glDisable(GL_DEPTH_TEST)
  glDisable(GL_TEXTURE_2D)
  glEnable(GL_BLEND)
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)

  if target != "Fullscreen":
    result.window.setWindowPos(wInfo.x, wInfo.y)

proc update*(self: Overlay) =
  self.window.swapBuffers()
  glfwPollEvents()
  glClear(GL_COLOR_BUFFER_BIT)

proc deinit*(self: Overlay) =
  self.window.destroyWindow()
  glfwTerminate()

proc close*(self: Overlay) = 
  self.window.setWindowShouldClose(true) 

proc loop*(self: Overlay, update: bool = true): bool =
  if update: 
    self.update()
  if keyPressed(self.exitKey): 
    self.close()
  not self.window.windowShouldClose()

#[
  2d drawings
]#

proc box*(x, y, width, height, lineWidth: float, color: Rgb) =
  glLineWidth(lineWidth)
  glBegin(GL_LINE_LOOP)
  glColor3f(color.r, color.g, color.b)
  glVertex2f(x, y)
  glVertex2f(x + width, y)
  glVertex2f(x + width, y + height)
  glVertex2f(x, y + height)
  glEnd()

proc alphaBox*(x, y, width, height: float, color, outlineColor: Rgb, alpha: float) =
  box(x, y, width, height, 1.0, outlineColor)
  glEnable(GL_BLEND)
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)
  glBegin(GL_POLYGON)
  glColor4f(color.r.float, color.g.float, color.b.float, alpha)
  glVertex2f(x, y)
  glVertex2f(x + width, y)
  glVertex2f(x + width, y + height)
  glVertex2f(x, y + height)
  glEnd()
  glDisable(GL_BLEND)

proc cornerBox*(x, y, width, height: float, color, outlineColor: Rgb, lineWidth: float = 1) =
  template drawCorner =
    glBegin(GL_LINES)
    # Lower Left
    glVertex2f(x, y); glVertex2f(x + lineW, y)
    glVertex2f(x, y); glVertex2f(x, y + lineH)

    # Lower Right
    glVertex2f(x + width, y); glVertex2f(x + width, y + lineH)
    glVertex2f(x + width, y); glVertex2f(x + width - lineW, y)

    # Upper Left
    glVertex2f(x, y + height); glVertex2f(x, y + height - lineH)
    glVertex2f(x, y + height); glVertex2f(x + lineW, y + height)

    # Upper Right
    glVertex2f(x + width, y + height); glVertex2f(x + width, y + height - lineH)
    glVertex2f(x + width, y + height); glVertex2f(x + width - lineW, y + height)
    glEnd()

  let
    lineW = width / 4
    lineH = height / 3

  glLineWidth(lineWidth + 2)
  glColor3f(outlineColor.r, outlineColor.g, outlineColor.b)
  drawCorner()
  glLineWidth(lineWidth)
  glColor3f(color.r, color.g, color.b)
  drawCorner()

proc line*(x1, y1, x2, y2, lineWidth: float, color: Rgb) =
  glLineWidth(lineWidth)
  glBegin(GL_LINES)
  glColor3f(color.r, color.g, color.b)
  glVertex2f(x1, y1)
  glVertex2f(x2, y2)
  glEnd()

proc dashedLine*(x1, y1, x2, y2, lineWidth: float, color: Rgb, factor: int32 = 2, pattern: string = "11111110000", alpha: float32 = 0.5) =
  glPushAttrib(GL_ENABLE_BIT)
  glLineStipple(factor, fromBin[uint16](pattern))
  glLineWidth(lineWidth)
  glEnable(GL_LINE_STIPPLE)
  glEnable(GL_BLEND)
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)

  glBegin(GL_LINES)
  glColor4f(color.r.float, color.g.float, color.b.float, alpha)
  glVertex2f(x1, y1)
  glVertex2f(x2, y2)
  glEnd()
  glPopAttrib()

proc circle*(x, y, radius: float, color: Rgb, filled: bool = true) =
  if filled: glBegin(GL_POLYGON)
  else: glBegin(GL_LINE_LOOP)

  glColor3f(color.r, color.g, color.b)
  for i in 0..<360:
    glVertex2f(
      cos(degToRad(i.float32)) * radius + x,
      sin(degToRad(i.float32)) * radius + y
    )
  glEnd()

proc radCircle*(x, y, radius: float, value: int, color: Rgb) =
  glBegin(GL_POLYGON)
  glColor3f(color.r, color.g, color.b)
  for i in 0..value:
    glVertex2f(
      cos(degToRad(i.float32)) * radius + x,
      sin(degToRad(i.float32)) * radius + y
    )
  glEnd()

proc valueBar*(x1, y1, x2, y2, width, maxValue, value: float, vertical: bool = true)  =
  if value > maxValue:
    raise newException(Exception, "ValueBar: Max Value > value")

  let
    x = value / maxValue
    barY = (y2 - y1) * x + y1
    barX = (x2 - x1) * x + x1
    color = newRgb(2 * (1 - x), 2 * x, 0)

  line(x1, y1, x2, y2, width + 3.0, newRgb(0, 0, 0))

  if vertical:
    line(x1, y1, x2, barY, width, color)
  else:
    line(x1, y1, barX, y2, width, color)

proc renderString*(x, y: float, text: string, color: Rgb, align: bool = false) =
  glColor3f(color.r, color.g, color.b)

  if align:
    glRasterPos2f(x - (glutBitmapLength(GLUT_BITMAP_HELVETICA_12, text).float / 2), y)
  else:
    glRasterPos2f(x, y)

  for c in text:
    glutBitmapCharacter(GLUT_BITMAP_HELVETICA_12, ord(c))