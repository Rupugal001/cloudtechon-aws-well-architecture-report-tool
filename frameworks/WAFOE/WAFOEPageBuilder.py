from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class WAFOEPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    