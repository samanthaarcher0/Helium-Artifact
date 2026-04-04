#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>

#include "/firefox/firefox/gfx/2d/SkConvolver.cpp"

using namespace skia;

int main() {
  const int width = 3;
  const int height = 1;
  uint8_t srcRow[] = {
    255, 255, 255, 255,  // white
    128, 128, 128, 255,  // gray
    10,   10,   10,   255   // black
  };

  std::vector<SkConvolutionFilter1D::ConvolutionFixed> horizKernel = {
    static_cast<SkConvolutionFilter1D::ConvolutionFixed>(.25 * (1 << SkConvolutionFilter1D::kShiftBits)),
    static_cast<SkConvolutionFilter1D::ConvolutionFixed>(.5 * (1 << SkConvolutionFilter1D::kShiftBits)),
    static_cast<SkConvolutionFilter1D::ConvolutionFixed>(.25 * (1 << SkConvolutionFilter1D::kShiftBits))  
   // static_cast<SkConvolutionFilter1D::ConvolutionFixed>(10),
   // static_cast<SkConvolutionFilter1D::ConvolutionFixed>(10),
   // static_cast<SkConvolutionFilter1D::ConvolutionFixed>(10)
  };

  SkConvolutionFilter1D horizFilter;
  horizFilter.AddFilter(0, horizKernel.data(), horizKernel.size());

  uint8_t horizOutput[width * 4] = {};
  convolve_horizontally(srcRow, horizFilter, horizOutput, true);
 // std::cout << "Horizontal Convolve Output: [ ";
 // for (int i = 0; i < width * 4; ++i) std::cout << (int)horizOutput[i] << " ";
 // std::cout << "]\n";

  //horizFilter.AddFilter(1, horizKernel.data(), horizKernel.size());
  //convolve_horizontally(srcRow, horizFilter, horizOutput, true);
  //std::cout << "Horizontal Convolve Output: [ ";
  //for (int i = 0; i < width * 4; ++i) std::cout << (int)horizOutput[i] << " ";
  //std::cout << "]\n";
  
  //horizFilter.AddFilter(2, horizKernel.data(), horizKernel.size());
  //convolve_horizontally(srcRow, horizFilter, horizOutput, true);
  //std::cout << "Horizontal Convolve Output: [ ";
  //for (int i = 0; i < width * 4; ++i) std::cout << (int)horizOutput[i] << " ";
  //std::cout << "]\n";

  uint8_t row0[] = {255, 255, 255, 255};
  uint8_t row1[] = {128, 128, 128, 255};
  uint8_t row2[] = {10, 10, 10, 255};
  uint8_t* verticalRows[] = {row0, row1, row2};
  uint8_t verticalOut[4];

//  convolve_vertically(horizKernel.data(), horizKernel.size(), verticalRows, 1, verticalOut, true);
//  std::cout << "Vertical Convolve Output: [ ";
//  for (int i = 0; i < 4; ++i) std::cout << (int)verticalOut[i] << " ";
 // std::cout << "]\n";

  return 0;
}

