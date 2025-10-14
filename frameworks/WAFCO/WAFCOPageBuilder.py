from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class WAFCOPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    